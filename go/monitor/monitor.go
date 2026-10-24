// Package monitor is the kid agent's monitoring loop: daily usage accounting,
// low-time warnings, lock enforcement and the parent actions that change them.
// It is a port of src/kid_pc_monitor/pc_time_control.py and implements
// dispatcher.Control.
//
// testdata/monitor/vectors.json is generated from the Python implementation by
// tests/monitor_vectors_gen.py: scripted scenarios against a fake clock and
// platform, recording every platform call, log line, state-file write and the
// in-memory state after each step. vectors_test.go replays them.
//
// # Concurrency
//
// A Control is safe for concurrent use: the loop (Run) and the request
// dispatcher call it from different goroutines. The lock is released around
// platform calls, so a slow popup never stalls a parent's request.
//
// # Differences from the Python agent
//
//   - Nothing is printed to a console; everything goes to the logger.
//   - SetBedTime/SetWakeTime do not validate their arguments (the dispatcher
//     already has).
package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"kidpcmonitor/policy"
	"kidpcmonitor/state"
)

// Platform is the operating-system side: session state, lock, popups, shutdown.
// Any method may fail; the monitor never lets that stop enforcement.
type Platform interface {
	CheckSessionLocked() (bool, error)
	// SessionIsActive reports whether this session is the active console
	// session and not locked.
	SessionIsActive() (bool, error)
	LockWorkstation() error
	Shutdown(seconds int64) error
	CancelShutdown() error
	ShowMessage(message, title string) error
	Hostname() string
}

// Config describes a Control. Only Platform, CurrentUser and DataDir are required.
type Config struct {
	Platform       Platform
	MonitoredUsers []string
	ExemptUsers    []string
	CurrentUser    string
	// DataDir holds the state files and pc_control.log.
	DataDir string
	// ProgramDataDir holds installer-provided settings; empty disables them.
	ProgramDataDir string
	// Clock returns naive wall-clock time (see policy.Wall). Defaults to the
	// system clock at microsecond resolution.
	Clock func() time.Time
	// Logger receives the agent's log lines. Defaults to slog.Default.
	Logger *slog.Logger
	// StateLogger receives the state store's own warnings. Defaults to Logger.
	StateLogger *slog.Logger
}

const (
	persistInterval  = 60 * time.Second
	maxTickGap       = 60 // seconds; longer gaps are not credited
	defaultAgentLog  = "pc_control.log"
	parentMessageMax = 120
)

var warningIntervals = []int{1, 5, 15, 30} // minutes before lock, ascending

// Control is the agent's time-control state and loop.
type Control struct {
	mu sync.Mutex

	platform      Platform
	monitored     []string
	exempt        []string
	currentUser   string
	clock         func() time.Time
	log           *slog.Logger
	store         *state.Store
	agentLogPath  string
	daily         state.DailySettings
	runtime       state.RuntimeState
	stateLoadFail bool
	lastTickAt    *time.Time
	lastPersistAt *time.Time
	isLocked      bool
	warningsSent  map[string]bool
	warningsDate  policy.Date
	lastLogReason *string
	failures      map[string]string
}

// New returns a Control with its state loaded from cfg.DataDir.
func New(cfg Config) (*Control, error) {
	if cfg.Platform == nil {
		return nil, fmt.Errorf("monitor: Config.Platform is required")
	}
	clock := cfg.Clock
	if clock == nil {
		clock = func() time.Time { return policy.Wall(time.Now()).Truncate(time.Microsecond) }
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	if err := os.MkdirAll(cfg.DataDir, 0o755); err != nil {
		return nil, err
	}
	store := state.NewStore(cfg.DataDir, cfg.CurrentUser)
	store.Clock = clock
	store.ProgramDataDir = cfg.ProgramDataDir
	store.Logger = cfg.StateLogger
	if store.Logger == nil {
		store.Logger = logger
	}

	c := &Control{
		platform:     cfg.Platform,
		monitored:    cfg.MonitoredUsers,
		exempt:       cfg.ExemptUsers,
		currentUser:  cfg.CurrentUser,
		clock:        clock,
		log:          logger,
		store:        store,
		agentLogPath: filepath.Join(cfg.DataDir, defaultAgentLog),
		daily:        state.DailySettings{WakeTime: policy.DefaultWakeTime},
		runtime:      state.FreshRuntimeState(clock()),
		warningsSent: map[string]bool{},
		failures:     map[string]string{},
	}
	if c.shouldMonitor() {
		c.log.Info("Monitoring enabled for user: " + c.currentUser)
	} else {
		c.log.Info("User " + c.currentUser + " is EXEMPT from monitoring")
	}
	c.loadState()
	c.warningsDate = policy.UsagePeriodDate(clock(), c.daily.WakeTime)
	return c, nil
}

// --- logging helpers --------------------------------------------------------

func (c *Control) info(format string, args ...any)   { c.log.Info(fmt.Sprintf(format, args...)) }
func (c *Control) errorf(format string, args ...any) { c.log.Error(fmt.Sprintf(format, args...)) }
func (c *Control) debug(msg string)                  { c.log.Debug(msg) }

// unlocked runs f (a platform call) with c.mu released. c.mu must be held.
func (c *Control) unlocked(f func()) {
	c.mu.Unlock()
	defer c.mu.Lock()
	f()
}

// noteFailure logs a repeating failure once, until it changes or clears.
func (c *Control) noteFailure(key, message string) {
	if c.failures[key] != message {
		c.failures[key] = message
		c.errorf("%s", message)
	}
}

func (c *Control) noteRecovered(key string) {
	if _, failing := c.failures[key]; failing {
		delete(c.failures, key)
		c.info("%s recovered", key)
	}
}

// --- state ------------------------------------------------------------------

func (c *Control) shouldMonitor() bool {
	return policy.ShouldMonitorUser(c.currentUser, c.monitored, c.exempt)
}

func pyBool(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func (c *Control) loadState() {
	daily, runtime, err := c.store.Load()
	if err != nil {
		c.stateLoadFail = true
		c.errorf("Error loading state: %v", err)
		return
	}
	c.daily, c.runtime, c.stateLoadFail = daily, runtime, false
	for _, p := range c.store.Problems {
		c.errorf("State file problem: %s %s (%s)", p.File, strings.ReplaceAll(p.Action, "_", " "), p.Reason)
	}
	bed := "none"
	if daily.BedTime != nil {
		bed = daily.BedTime.String()
	}
	allowance, effective := "none", "none"
	if daily.Allowance != nil {
		allowance = fmt.Sprintf("%d", *daily.Allowance)
	}
	if minutes, ok := state.EffectiveDailyAllowanceMinutes(daily, runtime); ok {
		effective = fmt.Sprintf("%.1f", minutes)
	}
	c.info("State applied: bed_time=%s wake_time=%s daily_allowance=%s effective_allowance=%s "+
		"manual_lock=%s accumulated_min=%.1f extension_sec=%d",
		bed, daily.WakeTime, allowance, effective, pyBool(runtime.ManualLockActive),
		runtime.AccumulatedSeconds/60, runtime.CumulativeExtensionSeconds)
}

// LoadState re-reads the state files.
func (c *Control) LoadState() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.loadState()
}

func (c *Control) saveState() {
	if c.stateLoadFail {
		// Retry the load: until it works, the in-memory defaults must not
		// overwrite whatever is on disk.
		c.loadState()
		if c.stateLoadFail {
			c.errorf("State files unreadable; not saving over them")
			return
		}
	}
	if err := c.store.Save(c.daily, &c.runtime); err != nil {
		c.errorf("Error saving state: %v", err)
		return
	}
	c.debug("State saved")
}

// SaveState writes the daily settings and runtime state.
func (c *Control) SaveState() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.saveState()
}

// --- platform queries -------------------------------------------------------

// checkIfLocked reports whether the workstation is locked. If the platform
// cannot say, assume it is not: enforcement then issues a lock instead of
// trusting a state it could not verify.
func (c *Control) checkIfLocked() bool {
	var locked bool
	var err error
	c.unlocked(func() { locked, err = c.platform.CheckSessionLocked() })
	if err != nil {
		c.noteFailure("check_session_locked", "Platform check_session_locked failed: "+err.Error())
		return false
	}
	c.noteRecovered("check_session_locked")
	return locked
}

// sessionIsActive reports whether this is the active, unlocked session. If the
// platform cannot say, assume it is: the time is counted rather than skipped.
func (c *Control) sessionIsActive() bool {
	var active bool
	var err error
	c.unlocked(func() { active, err = c.platform.SessionIsActive() })
	if err != nil {
		c.noteFailure("session_is_active", "Platform session_is_active failed: "+err.Error())
		return true
	}
	c.noteRecovered("session_is_active")
	return active
}

// --- policy -----------------------------------------------------------------

func (c *Control) effectiveAllowance() *float64 {
	if minutes, ok := state.EffectiveDailyAllowanceMinutes(c.daily, c.runtime); ok {
		return &minutes
	}
	return nil
}

func (c *Control) inputs(now time.Time) policy.Inputs {
	wake := c.daily.WakeTime
	return policy.Inputs{
		Now:                now,
		BedTime:            c.daily.BedTime,
		AllowanceMinutes:   c.effectiveAllowance(),
		AccumulatedMinutes: c.runtime.AccumulatedSeconds / 60,
		Exempt:             !c.shouldMonitor(),
		ManualLockActive:   c.runtime.ManualLockActive,
		WakeTime:           &wake,
	}
}

func (c *Control) currentlyInLockWindow() (bool, string) {
	d := policy.LockDecision(c.inputs(c.clock()))
	return d.ShouldLock, d.Reason
}

func (c *Control) timeRemaining() (float64, bool) {
	return policy.MinutesUntilLock(c.inputs(c.clock()))
}

func (c *Control) enforcementLockState() (bool, string) {
	return policy.EnforcementState(c.inputs(c.clock()))
}

// --- the loop ---------------------------------------------------------------

func (c *Control) resetRuntimeIfNeeded(now time.Time) bool {
	usedMinutes := c.runtime.AccumulatedSeconds / 60
	extension := c.runtime.CumulativeExtensionSeconds
	if !state.ResetRuntimeIfNeeded(&c.runtime, c.daily.WakeTime, now) {
		return false
	}
	c.info("Wake-time rollover (%s): resetting daily runtime state (was %.1f min used, %d extension sec)",
		c.daily.WakeTime, usedMinutes, extension)
	return true
}

// tickAccumulator advances the active-use counter by the seconds elapsed since
// the last active tick. It resets at wake time each day.
func (c *Control) tickAccumulator() {
	now := c.clock()
	if c.resetRuntimeIfNeeded(now) {
		c.lastTickAt = nil
	}

	// Never credit usage while a lock window is active (bedtime curfew or
	// manual lock): a brief detection flicker during curfew must not inflate usage.
	inLockWindow, _ := c.currentlyInLockWindow()

	if c.shouldMonitor() && c.sessionIsActive() && !inLockWindow {
		if c.lastTickAt != nil {
			// timedelta.total_seconds(): whole microseconds divided by 1e6.
			delta := float64(now.Sub(*c.lastTickAt).Microseconds()) / 1e6
			// Negative: the clock went backwards. Over a minute: the loop
			// stalled or the PC slept; the whole gap is not credited.
			if delta > 0 && delta < maxTickGap {
				c.runtime.AccumulatedSeconds += delta
			}
		}
		c.lastTickAt = &now
		return
	}
	c.lastTickAt = nil
}

func (c *Control) checkAndSendWarnings() error {
	// Clear sent-warning memory at wake time so the 30/15/5/1-minute warnings
	// fire again for the next usage period if the agent runs continuously.
	today := policy.UsagePeriodDate(c.clock(), c.daily.WakeTime)
	if today != c.warningsDate {
		clear(c.warningsSent)
		c.warningsDate = today
	}

	remaining, ok := c.timeRemaining()
	if !ok || remaining <= 0 {
		return nil
	}

	// Fire the smallest applicable threshold first so a kid with only a few
	// minutes left doesn't get a misleading "15 minutes" popup. Once a smaller
	// threshold fires, the larger ones are marked sent too: those windows never
	// applied to this session.
	for _, mins := range warningIntervals {
		key := fmt.Sprintf("%dmin", mins)
		if c.warningsSent[key] || remaining > float64(mins) {
			continue
		}
		actual := max(1, int(math.Ceil(remaining)))
		unit := "minutes"
		if actual == 1 {
			unit = "minute"
		}
		msg := fmt.Sprintf("⚠️ Computer will lock in %d %s!", actual, unit)

		// Only a popup that was shown counts as sent; a failed one is retried.
		if err := c.showMessage(msg, "Warning"); err != nil {
			return err
		}
		c.warningsSent[key] = true
		for _, larger := range warningIntervals {
			if larger > mins {
				c.warningsSent[fmt.Sprintf("%dmin", larger)] = true
			}
		}
		c.info("Warning sent: %d %s remaining (threshold %d)", actual, unit, mins)
		return nil
	}
	return nil
}

func (c *Control) showMessage(message, title string) error {
	var err error
	c.unlocked(func() { err = c.platform.ShowMessage(message, title) })
	return err
}

func (c *Control) lockPC() {
	var err error
	c.unlocked(func() { err = c.platform.LockWorkstation() })
	if err != nil {
		c.errorf("Error locking PC: %v", err)
		return
	}
	c.isLocked = true
}

func (c *Control) enforceLockWindow() error {
	locked, reason := c.currentlyInLockWindow()
	if locked && !c.checkIfLocked() {
		if c.lastLogReason == nil || *c.lastLogReason != reason {
			c.info("Locking PC: %s", reason)
			c.lastLogReason = &reason
		}
		c.lockPC()
	} else if !locked {
		c.lastLogReason = nil
	}
	return nil
}

func (c *Control) persistIfDue() error {
	// Persist the accumulator periodically so a crash or power loss doesn't
	// hand the kid a free reset of their daily usage. A clock that went
	// backwards counts as due, so saving never stalls for hours.
	now := c.clock()
	if c.lastPersistAt != nil {
		if elapsed := now.Sub(*c.lastPersistAt); elapsed >= 0 && elapsed < persistInterval {
			return nil
		}
	}
	c.saveState()
	c.lastPersistAt = &now
	return nil
}

// runPhase runs one loop phase, turning an error or panic into a log line.
func (c *Control) runPhase(name string, phase func() error) {
	err := func() (err error) {
		defer func() {
			if r := recover(); r != nil {
				err = fmt.Errorf("%v", r)
			}
		}()
		return phase()
	}()
	if err != nil {
		c.noteFailure(name, fmt.Sprintf("Monitor phase %s failed: %v", name, err))
		return
	}
	c.noteRecovered(name)
}

// Step runs one iteration of the monitoring loop (everything but the sleep).
// Each phase runs on its own: an error in one (a failing popup, say) is logged
// and never stops the others, least of all lock enforcement.
func (c *Control) Step() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runPhase("tick_accumulator", func() error { c.tickAccumulator(); return nil })
	c.runPhase("check_and_send_warnings", c.checkAndSendWarnings)
	c.runPhase("enforce_lock_window", c.enforceLockWindow)
	c.runPhase("persist_state", c.persistIfDue)
}

// Tick credits elapsed active time (one phase of Step, exposed for tests).
func (c *Control) Tick() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tickAccumulator()
}

// CheckAndSendWarnings sends the low-time popup that is due, if any.
func (c *Control) CheckAndSendWarnings() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checkAndSendWarnings()
}

// ObserveLockState notes lock/unlock transitions (kept for parity; it only
// updates the remembered lock flag).
func (c *Control) ObserveLockState() {
	c.mu.Lock()
	defer c.mu.Unlock()
	actual := c.checkIfLocked()
	if c.isLocked && !actual {
		c.isLocked = false
	}
}

// Run steps the monitor once a second, and watches lock transitions every
// three, until ctx is cancelled.
func (c *Control) Run(ctx context.Context) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for n := 0; ; n++ {
		c.Step()
		if n%3 == 0 {
			c.ObserveLockState()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// --- dispatcher.Control: reads ----------------------------------------------

func (c *Control) Hostname() string { return c.platform.Hostname() }

func (c *Control) CurrentUser() string { return c.currentUser }

func (c *Control) AgentLogPath() string { return c.agentLogPath }

func (c *Control) ScreenLocked() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.checkIfLocked()
}

func (c *Control) DailyAllowance() *int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.daily.Allowance == nil {
		return nil
	}
	v := *c.daily.Allowance
	return &v
}

func (c *Control) BedTime() *policy.TimeOfDay {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.daily.BedTime == nil {
		return nil
	}
	v := *c.daily.BedTime
	return &v
}

func (c *Control) WakeTime() policy.TimeOfDay {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.daily.WakeTime
}

func (c *Control) ManualLockActive() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runtime.ManualLockActive
}

func (c *Control) CumulativeExtensionSeconds() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runtime.CumulativeExtensionSeconds
}

func (c *Control) AccumulatedSeconds() float64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.runtime.AccumulatedSeconds
}

func (c *Control) TimeRemainingMinutes() (float64, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.timeRemaining()
}

func (c *Control) EnforcementLockState() (bool, string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.enforcementLockState()
}

func (c *Control) AccessStatus() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	active, reason := c.enforcementLockState()
	return policy.FormatAccessStatus(c.runtime.ManualLockActive, active, reason, c.checkIfLocked())
}

// --- dispatcher.Control: actions --------------------------------------------

func (c *Control) SetBedTime(hour, minute int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.daily.BedTime = &policy.TimeOfDay{Hour: hour, Minute: minute}
	c.info("Parent action: bed time set to %02d:%02d", hour, minute)
}

func (c *Control) ClearBedTime() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.daily.BedTime = nil
	c.info("Parent action: bed time cleared")
}

// SetWakeTime sets the daily morning unlock time (end of the bedtime curfew).
// Moving it so that the current usage period is a later one starts a new period.
func (c *Control) SetWakeTime(hour, minute int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.clock()
	previous := c.daily.WakeTime
	c.daily.WakeTime = policy.TimeOfDay{Hour: hour, Minute: minute}
	if policy.UsagePeriodDate(now, previous).Before(policy.UsagePeriodDate(now, c.daily.WakeTime)) {
		c.info("Wake-time change (%s -> %s): resetting daily runtime state (was %.1f min used, %d extension sec)",
			previous, c.daily.WakeTime, c.runtime.AccumulatedSeconds/60, c.runtime.CumulativeExtensionSeconds)
		state.ResetRuntimeForNewPeriod(&c.runtime, now)
		c.lastTickAt = nil
		clear(c.warningsSent)
	}
	c.warningsDate = policy.UsagePeriodDate(now, c.daily.WakeTime)
	c.info("Parent action: wake time set to %02d:%02d", hour, minute)
}

func (c *Control) SetDailyAllowance(minutes *int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.daily.Allowance = minutes; minutes == nil {
		c.info("Parent action: daily limit cleared")
	} else {
		c.info("Parent action: daily limit set to %d minutes", *minutes)
	}
}

// ExtendTime adds temporary extra allowance for the current usage period and
// lifts a manual lock.
func (c *Control) ExtendTime(minutes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runtime.CumulativeExtensionSeconds += minutes * 60
	c.runtime.ManualLockActive = false
	clear(c.warningsSent)
	c.info("Parent action: extended time by %d minutes", minutes)
}

func (c *Control) ClearExtensions() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runtime.CumulativeExtensionSeconds = 0
	c.info("Parent action: time extensions cleared")
}

// ClearWarnings forgets which low-time warnings were already sent.
func (c *Control) ClearWarnings() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.warningsSent)
}

// SendParentMessage shows a parent-initiated popup and records it in the log.
func (c *Control) SendParentMessage(message string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	preview := message
	if utf8.RuneCountInString(message) > parentMessageMax {
		preview = string([]rune(message)[:parentMessageMax]) + "..."
	}
	c.info("Parent action: message sent: %s", preview)
	return c.showMessage(message, "PC Time Control")
}

func (c *Control) EngageManualLock() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runtime.ManualLockActive = true
	c.lockPC()
	c.info("Parent action: manual lock engaged")
}

func (c *Control) ClearManualLock() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.runtime.ManualLockActive = false
	c.info("Parent action: manual lock cleared")
}

// LockPC locks the workstation for this session.
func (c *Control) LockPC() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lockPC()
}

func (c *Control) ShutdownPC(seconds int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	var err error
	c.unlocked(func() { err = c.platform.Shutdown(seconds) })
	if err != nil {
		c.errorf("Error initiating shutdown: %v", err)
		return
	}
	c.info("Parent action: shutdown in %ds", seconds)
}

// CancelShutdown cancels a pending shutdown.
func (c *Control) CancelShutdown() error {
	return c.platform.CancelShutdown()
}

// warningsSentSorted is the sent warning keys in order (for tests).
func (c *Control) warningsSentSorted() []string {
	keys := make([]string, 0, len(c.warningsSent))
	for k := range c.warningsSent {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
