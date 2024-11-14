// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64

package containerhook

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

type execruntimeRecord struct {
	MntnsId    uint64
	Pid        uint32
	ArgsSize   uint32
	CallerComm [16]uint8
	Args       [15360]uint8
}

// loadExecruntime returns the embedded CollectionSpec for execruntime.
func loadExecruntime() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ExecruntimeBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load execruntime: %w", err)
	}

	return spec, err
}

// loadExecruntimeObjects loads execruntime and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*execruntimeObjects
//	*execruntimePrograms
//	*execruntimeMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadExecruntimeObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadExecruntime()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// execruntimeSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type execruntimeSpecs struct {
	execruntimeProgramSpecs
	execruntimeMapSpecs
}

// execruntimeSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type execruntimeProgramSpecs struct {
	IgExecveE   *ebpf.ProgramSpec `ebpf:"ig_execve_e"`
	IgExecveX   *ebpf.ProgramSpec `ebpf:"ig_execve_x"`
	IgFaPickE   *ebpf.ProgramSpec `ebpf:"ig_fa_pick_e"`
	IgFaPickX   *ebpf.ProgramSpec `ebpf:"ig_fa_pick_x"`
	IgSchedExec *ebpf.ProgramSpec `ebpf:"ig_sched_exec"`
}

// execruntimeMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type execruntimeMapSpecs struct {
	ExecArgs    *ebpf.MapSpec `ebpf:"exec_args"`
	IgFaPickCtx *ebpf.MapSpec `ebpf:"ig_fa_pick_ctx"`
	IgFaRecords *ebpf.MapSpec `ebpf:"ig_fa_records"`
}

// execruntimeObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadExecruntimeObjects or ebpf.CollectionSpec.LoadAndAssign.
type execruntimeObjects struct {
	execruntimePrograms
	execruntimeMaps
}

func (o *execruntimeObjects) Close() error {
	return _ExecruntimeClose(
		&o.execruntimePrograms,
		&o.execruntimeMaps,
	)
}

// execruntimeMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadExecruntimeObjects or ebpf.CollectionSpec.LoadAndAssign.
type execruntimeMaps struct {
	ExecArgs    *ebpf.Map `ebpf:"exec_args"`
	IgFaPickCtx *ebpf.Map `ebpf:"ig_fa_pick_ctx"`
	IgFaRecords *ebpf.Map `ebpf:"ig_fa_records"`
}

func (m *execruntimeMaps) Close() error {
	return _ExecruntimeClose(
		m.ExecArgs,
		m.IgFaPickCtx,
		m.IgFaRecords,
	)
}

// execruntimePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadExecruntimeObjects or ebpf.CollectionSpec.LoadAndAssign.
type execruntimePrograms struct {
	IgExecveE   *ebpf.Program `ebpf:"ig_execve_e"`
	IgExecveX   *ebpf.Program `ebpf:"ig_execve_x"`
	IgFaPickE   *ebpf.Program `ebpf:"ig_fa_pick_e"`
	IgFaPickX   *ebpf.Program `ebpf:"ig_fa_pick_x"`
	IgSchedExec *ebpf.Program `ebpf:"ig_sched_exec"`
}

func (p *execruntimePrograms) Close() error {
	return _ExecruntimeClose(
		p.IgExecveE,
		p.IgExecveX,
		p.IgFaPickE,
		p.IgFaPickX,
		p.IgSchedExec,
	)
}

func _ExecruntimeClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed execruntime_x86_bpfel.o
var _ExecruntimeBytes []byte
