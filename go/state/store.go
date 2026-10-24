package state

import (
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
	backupSuffix         = ".bak"
	quarantineSuffix     = ".corrupt-"
	quarantineTimeLayout = "20060102T150405"
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

// Problem is something wrong with a state file that Load worked around.
type Problem struct {
	File   string
	Action string // "quarantined", "restored_from_backup" or "ignored"
	Reason string
}

// Store reads and writes daily_settings.json and state.json under DataDir.
//
// Files are never silently discarded. A file that exists but is unusable is
// renamed to <name>.corrupt-<timestamp>; the last good copy (<name>.bak,
// refreshed on every Save) is restored in its place, and only if there is none
// do defaults apply. A file that has simply gone missing is restored from its
// backup too. Every such event is listed in Problems after Load.
type Store struct {
	DataDir     string
	CurrentUser string
	// Clock returns the current naive wall-clock time. Defaults to time.Now
	// with its location stripped (see policy.Wall).
	Clock func() time.Time
	// ProgramDataDir holds installer-provided settings; empty disables them.
	ProgramDataDir string
	// Logger receives warnings. Defaults to slog.Default.
	Logger *slog.Logger
	// Problems is reset by every Load.
	Problems []Problem
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

// loadJSONFile reads a JSON object from path. A missing file is (nil, "", nil).
// A file that exists but is unusable (not UTF-8, not JSON, NaN/Infinity, not
// an object) is (nil, reason, nil). err is an I/O failure: a file that could
// not be read at all is not a verdict on its content.
func loadJSONFile(path string) (doc Document, reason string, err error) {
	info, statErr := os.Stat(path)
	if statErr != nil || !info.Mode().IsRegular() {
		return nil, "", nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, "", err
	}
	doc, decodeErr := DecodeDocument(raw)
	if decodeErr != nil {
		return nil, "not valid JSON: " + decodeErr.Error(), nil
	}
	return doc, "", nil
}

// readLenient reads a file this package does not own (legacy or installer
// output): any problem is logged and treated as "not there".
func readLenient(path string, log *slog.Logger) Document {
	doc, reason, err := loadJSONFile(path)
	switch {
	case err != nil:
		log.Warn("could not read file", "path", path, "error", err)
	case reason != "":
		log.Warn("ignoring file", "path", path, "reason", reason)
	}
	return doc
}

func copyFile(from, to string) error {
	raw, err := os.ReadFile(from)
	if err != nil {
		return err
	}
	return os.WriteFile(to, raw, 0o644)
}

// writeJSON atomically replaces path, first keeping the current file as
// <path>.bak if (and only if) it is valid according to validate.
func writeJSON(path string, payload []byte, validate func(Document) error) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	current, reason, err := loadJSONFile(path)
	if err != nil {
		return err
	}
	if current != nil && reason == "" && validate(current) == nil {
		if err := copyFile(path, path+backupSuffix); err != nil {
			return err
		}
	}
	tmp := strings.TrimSuffix(path, ".json") + ".json.tmp"
	if err := os.WriteFile(tmp, payload, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

func (s *Store) writeDaily(d DailySettings) error {
	payload, err := DailyToJSON(d)
	if err != nil {
		return err
	}
	return writeJSON(s.dailyPath(), payload, func(doc Document) error {
		_, err := LoadDailyFromDocument(doc)
		return err
	})
}

func (s *Store) writeRuntime(r RuntimeState) error {
	payload, err := RuntimeToJSON(r)
	if err != nil {
		return err
	}
	return writeJSON(s.statePath(), payload, func(doc Document) error {
		_, err := LoadRuntimeFromDocument(doc)
		return err
	})
}

// Save stamps r with the current time and writes both files.
func (s *Store) Save(d DailySettings, r *RuntimeState) error {
	r.Timestamp = s.Clock()
	if err := s.writeDaily(d); err != nil {
		return err
	}
	return s.writeRuntime(*r)
}

func (s *Store) problem(file, action, reason string) {
	s.logger().Warn("state file problem", "file", file, "action", action, "reason", reason)
	s.Problems = append(s.Problems, Problem{file, action, reason})
}

func (s *Store) quarantine(path, reason string) {
	target := path + quarantineSuffix + s.Clock().Format(quarantineTimeLayout)
	if err := os.Rename(path, target); err != nil {
		s.logger().Error("could not move file aside", "path", path, "error", err)
	}
	s.problem(filepath.Base(path), "quarantined", reason)
}

// readValidated returns loader(file) for path, else for its backup, else nil.
func readValidated[T any](s *Store, path string, loader func(Document) (T, error)) (*T, error) {
	for _, candidate := range []string{path, path + backupSuffix} {
		doc, reason, err := loadJSONFile(candidate)
		if err != nil {
			return nil, err
		}
		if doc != nil {
			value, loadErr := loader(doc)
			if loadErr == nil {
				if candidate != path {
					if err := copyFile(candidate, path); err != nil {
						s.logger().Error("could not restore from backup", "path", path, "error", err)
					}
					s.problem(filepath.Base(path), "restored_from_backup", "from "+filepath.Base(candidate))
				}
				return &value, nil
			}
			reason = loadErr.Error()
		}
		if reason != "" {
			s.quarantine(candidate, reason)
		}
	}
	return nil, nil
}

// Load returns the saved settings and runtime state, creating or recovering
// files as needed. Counters from a previous usage period are reset in the
// returned value (not on disk).
//
// The error is non-nil only for I/O failures: a file that could not be read or
// written. Callers must not Save after a failed Load, or built-in defaults
// would replace the real files. Unusable content is never an error; see Store.
func (s *Store) Load() (DailySettings, RuntimeState, error) {
	s.Problems = nil
	daily, err := readValidated(s, s.dailyPath(), LoadDailyFromDocument)
	if err != nil {
		return DailySettings{}, RuntimeState{}, err
	}
	rt, err := readValidated(s, s.statePath(), LoadRuntimeFromDocument)
	if err != nil {
		return DailySettings{}, RuntimeState{}, err
	}
	runtimeOnDisk := rt != nil

	dailyDerived := daily == nil
	if daily == nil {
		d, legacyRuntime := s.deriveDaily()
		daily = &d
		if rt == nil {
			rt = legacyRuntime
		}
	}
	if rt == nil {
		fresh := FreshRuntimeState(s.Clock())
		rt = &fresh
	}

	if dailyDerived {
		// A fresh install, an upgrade from the legacy file, or settings that
		// could not be recovered: persist what we settled on.
		if err := s.writeDaily(*daily); err != nil {
			return *daily, *rt, err
		}
		if !runtimeOnDisk {
			rt.Timestamp = s.Clock()
			if err := s.writeRuntime(*rt); err != nil {
				return *daily, *rt, err
			}
		}
	}

	if ResetRuntimeIfNeeded(rt, daily.WakeTime, s.Clock()) {
		s.logger().Info("runtime state is from a previous usage period; resetting daily counters")
	}
	return *daily, *rt, nil
}

// deriveDaily finds settings (and maybe runtime) for an install with no usable
// daily_settings.json: the legacy file, then the installer's ProgramData
// settings, then defaults.
func (s *Store) deriveDaily() (DailySettings, *RuntimeState) {
	if legacy := readLenient(s.legacyPath(), s.logger()); legacy != nil {
		d, r, err := LegacyToState(legacy, s.Clock())
		if err == nil {
			s.logger().Info("migrated legacy state", "user", s.CurrentUser, "from", s.legacyPath())
			return d, &r
		}
		s.problem(LegacyStateFile, "ignored", err.Error())
	}
	if boot := s.bootstrapFromProgramData(); boot != nil {
		return *boot, nil
	}
	return DailySettings{WakeTime: policy.DefaultWakeTime}, nil
}

// targetUserMismatch reports whether doc names a different account than the
// one this agent runs as.
func (s *Store) targetUserMismatch(doc Document) bool {
	target, ok := doc["target_user"].(string)
	return ok && target != "" && strings.ToLower(target) != strings.ToLower(s.CurrentUser)
}

func (s *Store) bootstrapFromProgramData() *DailySettings {
	if s.ProgramDataDir == "" {
		return nil
	}
	log := s.logger()
	if doc := readLenient(filepath.Join(s.ProgramDataDir, DailySettingsFile), log); doc != nil && !s.targetUserMismatch(doc) {
		d, err := LoadDailyFromDocument(doc)
		if err == nil {
			return &d
		}
		log.Warn("invalid program-data daily settings", "error", err)
	}

	doc := readLenient(filepath.Join(s.ProgramDataDir, LegacyInstallConfig), log)
	if doc == nil || s.targetUserMismatch(doc) {
		return nil
	}
	if raw, ok := doc["wake_time"].(string); ok {
		if wake, err := policy.ParseTimeHHMM(raw); err == nil {
			return &DailySettings{WakeTime: wake}
		}
	}
	return nil
}

// FindCompleteDailySettings returns the first complete schedule found in the
// profile or ProgramData file, and which path it came from; nil if neither is
// complete. Used by the installer to offer reusing an existing schedule.
func FindCompleteDailySettings(profilePath, programDataPath string) (*DailySettings, string) {
	log := slog.Default()
	for _, path := range []string{profilePath, programDataPath} {
		if path == "" {
			continue
		}
		doc := readLenient(path, log)
		if doc == nil || !IsCompleteDailyDocument(doc) {
			continue
		}
		if d, err := LoadDailyFromDocument(doc); err == nil {
			return &d, path
		}
	}
	return nil, ""
}

// ProgramDataTargetUser returns the monitored account named in the ProgramData
// daily_settings.json, or "".
func ProgramDataTargetUser(programDataDir string) string {
	if programDataDir == "" {
		return ""
	}
	doc := readLenient(filepath.Join(programDataDir, DailySettingsFile), slog.Default())
	if target, ok := doc["target_user"].(string); ok {
		return strings.TrimFunc(target, isSpace)
	}
	return ""
}
