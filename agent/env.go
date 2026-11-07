package agent

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

// DataDir is the agent's per-user state directory: %LOCALAPPDATA%\KidPCMonitor
// (the home directory when LOCALAPPDATA is unset), as pc_time_control.data_dir.
func DataDir() string {
	base := os.Getenv("LOCALAPPDATA")
	if base == "" {
		base, _ = os.UserHomeDir()
	}
	return filepath.Join(base, "KidPCMonitor")
}

// CurrentUser is the login name as Python's getpass.getuser() finds it: the
// first of LOGNAME, USER, LNAME, USERNAME that is set, else the account name
// without its domain.
func CurrentUser() string {
	for _, k := range []string{"LOGNAME", "USER", "LNAME", "USERNAME"} {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	u, err := user.Current()
	if err != nil {
		return ""
	}
	name := u.Username
	if i := strings.LastIndexByte(name, '\\'); i >= 0 {
		name = name[i+1:]
	}
	return name
}
