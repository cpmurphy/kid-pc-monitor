package state

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"kidpcmonitor/policy"
)

const (
	DailySettingsFile    = "daily_settings.json"
	StateFile            = "state.json"
	LegacyStateFile      = "pc_control_state.json"
	LegacyInstallConfig  = "install_config.json"
	programDataSubfolder = "KidPCMonitor"
)

// PlatformProgramDataDir is where the installer leaves settings for the agent:
// %ProgramData%\KidPCMonitor on Windows, none elsewhere.
func PlatformProgramDataDir() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	base := os.Getenv("ProgramData")
	if base == "" {
		base = `C:\ProgramData`
	}
	return filepath.Join(base, programDataSubfolder)
}

// Store reads and writes daily_settings.json and state.json under DataDir.
type Store struct {
	DataDir     string
	CurrentUser string
	// Clock returns the current naive wall-clock time. Defaults to time.Now
	// with its location stripped (see policy.Wall).
	Clock func() time.Time
	// ProgramDataDir holds installer-provided settings; empty disables them.
	ProgramDataDir string
	// Logger receives warnings about unreadable files. Defaults to slog.Default.
	Logger *slog.Logger
}

// NewStore returns a Store for dataDir using the real clock and the platform's
// ProgramData directory.
func NewStore(dataDir, currentUser string) *Store {
	return &Store{
		DataDir:        dataDir,
		CurrentUser:    currentUser,
		Clock:          func() time.Time { return policy.Wall(time.Now()) },
		ProgramDataDir: PlatformProgramDataDir(),
	}
}

func (s *Store) logger() *slog.Logger {
	if s.Logger != nil {
		return s.Logger
	}
	return slog.Default()
}

func (s *Store) dailyPath() string  { return filepath.Join(s.DataDir, DailySettingsFile) }
func (s *Store) statePath() string  { return filepath.Join(s.DataDir, StateFile) }
func (s *Store) legacyPath() string { return filepath.Join(s.DataDir, LegacyStateFile) }

// readDocument returns the JSON object at path, or nil when the file is
// missing, unreadable or not JSON (a warning is logged for the last two).
func readDocument(path string, log *slog.Logger) (Document, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Warn("could not read file", "path", path, "error", err)
		return nil, nil
	}
	doc, err := DecodeDocument(raw)
	if err != nil {
		if errors.Is(err, errNotObject) { // valid JSON, but not an object
			return nil, err
		}
		log.Warn("could not read file", "path", path, "error", err)
		return nil, nil
	}
	return doc, nil
}

func writeJSON(path string, payload []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := strings.TrimSuffix(path, ".json") + ".json.tmp"
	if err := os.WriteFile(tmp, payload, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// Save stamps r with the current time and writes both files.
func (s *Store) Save(d DailySettings, r *RuntimeState) error {
	r.Timestamp = s.Clock()
	daily, err := DailyToJSON(d)
	if err != nil {
		return err
	}
	if err := writeJSON(s.dailyPath(), daily); err != nil {
		return err
	}
	state, err := RuntimeToJSON(*r)
	if err != nil {
		return err
	}
	return writeJSON(s.statePath(), state)
}

// Load returns the saved settings and runtime state, creating or migrating
// files as needed. Counters from a previous usage period are reset in the
// returned value (not on disk).
//
// An error means the files could not be interpreted; see the package comment
// for how Python's agent reacts.
func (s *Store) Load() (DailySettings, RuntimeState, error) {
	daily, err := s.loadDaily()
	if err != nil {
		return daily, RuntimeState{}, err
	}
	rt, err := s.loadRuntime()
	if err != nil {
		return daily, rt, err
	}
	if ResetRuntimeIfNeeded(&rt, daily.WakeTime, s.Clock()) {
		s.logger().Info("runtime state is from a previous usage period; resetting daily counters")
	}
	return daily, rt, nil
}

func (s *Store) migrateLegacy() (*DailySettings, *RuntimeState, error) {
	legacy, err := readDocument(s.legacyPath(), s.logger())
	if err != nil || legacy == nil {
		return nil, nil, err
	}
	d, r, err := LegacyToState(legacy, s.Clock())
	if err != nil {
		return nil, nil, err
	}
	s.logger().Info("migrated legacy state", "user", s.CurrentUser, "from", s.legacyPath())
	return &d, &r, nil
}

func (s *Store) loadDaily() (DailySettings, error) {
	data, err := readDocument(s.dailyPath(), s.logger())
	if err != nil {
		return DailySettings{}, err
	}
	if data != nil {
		return LoadDailyFromDocument(data)
	}

	d, r, err := s.migrateLegacy()
	if err != nil {
		return DailySettings{}, err
	}
	if d != nil {
		err := s.Save(*d, r)
		return *d, err
	}

	boot, err := s.bootstrapFromProgramData()
	if err != nil {
		return DailySettings{}, err
	}
	if boot != nil {
		fresh := FreshRuntimeState(s.Clock())
		err := s.Save(*boot, &fresh)
		return *boot, err
	}

	defaults := DailySettings{WakeTime: policy.DefaultWakeTime}
	fresh := FreshRuntimeState(s.Clock())
	err = s.Save(defaults, &fresh)
	return defaults, err
}

func (s *Store) loadRuntime() (RuntimeState, error) {
	data, err := readDocument(s.statePath(), s.logger())
	if err != nil {
		return RuntimeState{}, err
	}
	if data != nil {
		r, err := LoadRuntimeFromDocument(data)
		if err == nil {
			return r, nil
		}
		if !IsValueError(err) {
			return RuntimeState{}, err // a TypeError aborts the load, as in Python
		}
		s.logger().Warn("invalid state file; starting fresh", "path", s.statePath(), "error", err)
	}

	d, r, err := s.migrateLegacy()
	if err != nil {
		return RuntimeState{}, err
	}
	if d != nil {
		err := s.Save(*d, r) // stamps r with the clock
		return *r, err
	}
	return FreshRuntimeState(s.Clock()), nil
}

// targetUserMismatch reports whether doc names a different account than the
// one this agent runs as.
func (s *Store) targetUserMismatch(doc Document) bool {
	target, ok := doc["target_user"].(string)
	return ok && target != "" && strings.ToLower(target) != strings.ToLower(s.CurrentUser)
}

func (s *Store) bootstrapFromProgramData() (*DailySettings, error) {
	if s.ProgramDataDir == "" {
		return nil, nil
	}
	if doc, err := readDocument(filepath.Join(s.ProgramDataDir, DailySettingsFile), s.logger()); err != nil {
		return nil, err
	} else if doc != nil && !s.targetUserMismatch(doc) {
		d, err := LoadDailyFromDocument(doc)
		if err == nil {
			return &d, nil
		}
		if !IsValueError(err) {
			return nil, err
		}
		s.logger().Warn("invalid program-data daily settings", "error", err)
	}

	doc, err := readDocument(filepath.Join(s.ProgramDataDir, LegacyInstallConfig), s.logger())
	if err != nil || doc == nil || s.targetUserMismatch(doc) {
		return nil, err
	}
	if raw, ok := doc["wake_time"].(string); ok {
		if wake, err := policy.ParseTimeHHMM(raw); err == nil {
			return &DailySettings{WakeTime: wake}, nil
		}
	}
	return nil, nil
}

// FindCompleteDailySettings returns the first complete schedule found in the
// profile or ProgramData file, and which path it came from. Used by the
// installer to offer reusing an existing schedule.
func FindCompleteDailySettings(profilePath, programDataPath string) (*DailySettings, string, error) {
	log := slog.Default()
	for _, path := range []string{profilePath, programDataPath} {
		if path == "" {
			continue
		}
		doc, err := readDocument(path, log)
		if err != nil {
			return nil, "", err
		}
		if doc == nil || !IsCompleteDailyDocument(doc) {
			continue
		}
		if d, err := LoadDailyFromDocument(doc); err == nil {
			return &d, path, nil
		}
	}
	return nil, "", nil
}

// ProgramDataTargetUser returns the monitored account named in the ProgramData
// daily_settings.json, or "".
func ProgramDataTargetUser(programDataDir string) (string, error) {
	if programDataDir == "" {
		return "", nil
	}
	doc, err := readDocument(filepath.Join(programDataDir, DailySettingsFile), slog.Default())
	if err != nil || doc == nil {
		return "", err
	}
	if target, ok := doc["target_user"].(string); ok {
		return strings.TrimFunc(target, isSpace), nil
	}
	return "", nil
}
