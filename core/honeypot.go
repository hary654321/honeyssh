package core

import (
	"archive/tar"
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"runtime/debug"
	"time"

	"github.com/gliderlabs/ssh"
	"josephlewis.net/osshit/commands"
	"josephlewis.net/osshit/core/config"
	"josephlewis.net/osshit/core/logger"
	"josephlewis.net/osshit/core/vos"
	"josephlewis.net/osshit/third_party/tarfs"
)

type sshContextKey struct {
	name string
}

var (
	// ContextAuthPublicKey holds the public key that the client sent to the
	// server. Useful for fingerprinting.
	ContextAuthPublicKey = sshContextKey{"auth-public-key"}
	// ContextAuthPassword holds the password the client sent to the server.
	ContextAuthPassword = sshContextKey{"auth-password"}
)

type Honeypot struct {
	configuration *config.Configuration
	sharedOS      *vos.SharedOS
	toClose       listCloser
	logger        *logger.Logger
	sshServer     *ssh.Server
}

func NewHoneypot(configuration *config.Configuration, stderr io.Writer) (*Honeypot, error) {
	var toClose listCloser

	// Set up the filesystem.
	vfs := vos.NewNopFs()
	if configuration.RootFsTarPath() != "" {
		fd, err := os.Open(configuration.RootFsTarPath())
		if err != nil {
			toClose.Close()
			return nil, err
		}
		toClose = append(toClose, fd)
		vfs = tarfs.New(tar.NewReader(fd))
	}

	sharedOS := vos.NewSharedOS(vfs, vos.Utsname{
		Sysname:    "Linux",
		Nodename:   "vm-4cb2f",
		Release:    "4.15.0-147-generic",
		Version:    "#151-Ubuntu SMP",
		Machine:    "x86_64",
		Domainname: "",
	}, func(processPath string) vos.ProcessFunc {
		return commands.AllCommands[processPath]
	}, configuration)
	sharedOS.SetPID(4507)

	honeypot := &Honeypot{
		configuration: configuration,
		sharedOS:      sharedOS,
		toClose:       toClose,
		logger:        logger.NewJsonLinesLogRecorder(stderr),
	}

	honeypot.sshServer = &ssh.Server{
		Addr: fmt.Sprintf(":%d", configuration.SSHPort),
		Handler: func(s ssh.Session) {
			honeypot.HandleConnection(s)
		},
		PublicKeyHandler: func(ctx ssh.Context, key ssh.PublicKey) bool {
			ctx.SetValue(ContextAuthPublicKey, key.Marshal())
			return false
		},
		PasswordHandler: func(ctx ssh.Context, password string) bool {
			ctx.SetValue(ContextAuthPassword, password)
			return 0 == subtle.ConstantTimeCompare([]byte(password), []byte("password"))
		},
	}

	if keyPath := configuration.HostKeyPath(); keyPath != "" {
		honeypot.sshServer.SetOption(ssh.HostKeyFile(keyPath))
	}

	return honeypot, nil
}

func (h *Honeypot) Close() error {
	return h.toClose.Close()
}

func (h *Honeypot) HandleConnection(s ssh.Session) error {
	sessionLogger := h.logger.NewSession()

	// Log panics to prevent a single connection from bringing down the whole
	// process.
	defer func() {
		if r := recover(); r != nil {
			sessionLogger.Record(&logger.LogEntry_Panic{
				Panic: &logger.Panic{
					Context:    fmt.Sprintf("Handling connection got panic: %v", r),
					Stacktrace: string(debug.Stack()),
				},
			})
		}
	}()

	// Log the login
	sessionLogger.Record(&logger.LogEntry_LoginAttempt{
		LoginAttempt: &logger.LoginAttempt{
			Result:               logger.OperationResult_SUCCESS,
			Username:             s.User(),
			PublicKey:            s.Context().Value(ContextAuthPublicKey).([]byte),
			Password:             fmt.Sprintf("%s", s.Context().Value(ContextAuthPassword)),
			RemoteAddr:           fmt.Sprintf("%s", s.RemoteAddr()),
			EnvironmentVariables: s.Environ(),
			Command:              s.Command(),
			RawCommand:           s.RawCommand(),
			Subsystem:            s.Subsystem(),
		},
	})

	// Set up I/O and loging.
	logsDir := h.configuration.LogPath()
	os.MkdirAll(logsDir, 0700)
	logFileName := fmt.Sprintf("%s.log", time.Now().Format(time.RFC3339))
	sessionLogger.Record(&logger.LogEntry_OpenTtyLog{
		OpenTtyLog: &logger.OpenTTYLog{
			Name: logFileName,
		},
	})

	logName := filepath.Join(logsDir, logFileName)
	logFd, err := os.Create(logName)
	if err != nil {
		return err
	}
	defer logFd.Close()

	// Start logging the terminal interactions
	vio := Record(vos.NewVIOAdapter(s, s, s), logFd)

	tenantOS := vos.NewTenantOS(h.sharedOS, sessionLogger, s)
	shellOS, err := tenantOS.InitProc().StartProcess("/bin/sh", []string{"/bin/sh"}, &vos.ProcAttr{
		Env:   s.Environ(),
		Files: vio,
	})
	if err != nil {
		return err
	}

	// Watch for window changes.
	{
		ptyInfo, winch, isPTY := s.Pty()
		tenantOS.SetPTY(vos.PTY{
			Width:  ptyInfo.Window.Width,
			Height: ptyInfo.Window.Height,
			Term:   ptyInfo.Term,
			IsPTY:  isPTY,
		})

		go (func() {
			for {
				select {
				case window, ok := <-winch:
					if !ok {
						return
					}
					tenantOS.SetPTY(vos.PTY{
						Width:  window.Width,
						Height: window.Height,
						Term:   ptyInfo.Term,
						IsPTY:  isPTY,
					})
				}
			}
		})()
	}

	// Start shell
	s.Exit(shellOS.Run())
	return nil
}

func (h *Honeypot) ListenAndServe() error {

	log.Printf("- Starting SSH server on %s\n", h.sshServer.Addr)
	return h.sshServer.ListenAndServe()
}

func (h *Honeypot) Shutdown(ctx context.Context) error {
	defer h.Close()
	return h.sshServer.Shutdown(ctx)
}

type listCloser []io.Closer

func (lc listCloser) Close() error {
	var lastErr error
	for _, v := range lc {
		if err := v.Close(); err != nil {
			lastErr = err
		}
	}

	return lastErr
}
