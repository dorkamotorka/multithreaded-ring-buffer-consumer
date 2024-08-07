// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || arm || arm64 || loong64 || mips64le || mipsle || ppc64le || riscv64

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadProduce returns the embedded CollectionSpec for produce.
func loadProduce() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_ProduceBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load produce: %w", err)
	}

	return spec, err
}

// loadProduceObjects loads produce and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//	*produceObjects
//	*producePrograms
//	*produceMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadProduceObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadProduce()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// produceSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type produceSpecs struct {
	produceProgramSpecs
	produceMapSpecs
}

// produceSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type produceProgramSpecs struct {
	HandleExecve *ebpf.ProgramSpec `ebpf:"handle_execve"`
}

// produceMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type produceMapSpecs struct {
	ArrayMap  *ebpf.MapSpec `ebpf:"array_map"`
	EventsMap *ebpf.MapSpec `ebpf:"events_map"`
}

// produceObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadProduceObjects or ebpf.CollectionSpec.LoadAndAssign.
type produceObjects struct {
	producePrograms
	produceMaps
}

func (o *produceObjects) Close() error {
	return _ProduceClose(
		&o.producePrograms,
		&o.produceMaps,
	)
}

// produceMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadProduceObjects or ebpf.CollectionSpec.LoadAndAssign.
type produceMaps struct {
	ArrayMap  *ebpf.Map `ebpf:"array_map"`
	EventsMap *ebpf.Map `ebpf:"events_map"`
}

func (m *produceMaps) Close() error {
	return _ProduceClose(
		m.ArrayMap,
		m.EventsMap,
	)
}

// producePrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadProduceObjects or ebpf.CollectionSpec.LoadAndAssign.
type producePrograms struct {
	HandleExecve *ebpf.Program `ebpf:"handle_execve"`
}

func (p *producePrograms) Close() error {
	return _ProduceClose(
		p.HandleExecve,
	)
}

func _ProduceClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//
//go:embed produce_bpfel.o
var _ProduceBytes []byte
