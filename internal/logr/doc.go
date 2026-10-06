// Package logr adapts an xlog.KeyValueLogger to the go-logr LogSink
// interface so that controller-runtime logs through the same formatter as
// the rest of the process.
//
//	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Logger: logr.New(logger)})
//
// Info lines are logged at xlog.INFO for verbosity 0, TRACE for 1 and DEBUG
// for 2 and above; Error lines at xlog.ERROR with an err key. Names from
// WithName are logged under the src key. The sink is immutable: WithValues
// and WithName return new sinks.
package logr
