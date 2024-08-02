package main

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go produce produce.c

import (
    "log"
    "sync"
    "unsafe"

    "github.com/cilium/ebpf/rlimit"
    "github.com/cilium/ebpf/link"
    "github.com/cilium/ebpf/ringbuf"
)

type Event struct {
    Num  uint32
}

func main() {
    // Allow the current process to lock memory for eBPF resources.
    if err := rlimit.RemoveMemlock(); err != nil {
    	log.Fatal(err)
    }

    // Load pre-compiled programs and maps into the kernel.
    produceObjs := produceObjects{}
    if err := loadProduceObjects(&produceObjs, nil); err != nil {
    	log.Fatal(err)
    }
    defer produceObjs.Close()

    var key uint32 = 0
    var value uint32 = 1
    err := produceObjs.produceMaps.ArrayMap.Put(key, value); if err != nil {
	log.Printf("here")
	log.Fatal(err)
    }

    // Attach eBPF program
    tp, err := link.Tracepoint("syscalls", "sys_enter_execve", produceObjs.producePrograms.HandleExecve, nil)
    if err != nil {
        log.Fatalf("opening tracepoint: %v", err)
    }
    defer tp.Close()

    // Create a ring buffer reader
    rd, err := ringbuf.NewReader(produceObjs.produceMaps.EventsMap)
    if err != nil {
        log.Fatalf("creating ringbuf reader: %v", err)
    }
    defer rd.Close()

    // Create a wait group to synchronize goroutines
    var wg sync.WaitGroup

    for {
	record, err := rd.Read()
	if err != nil {
	    if err == ringbuf.ErrClosed {
		return
	    }
	    log.Printf("reading from ringbuf: %v", err)
	    continue
	}

	wg.Add(1)
	go func() {
	    defer wg.Done()
	
	    event := (*Event)(unsafe.Pointer(&record.RawSample[0]))
	    log.Printf("Num: %d", event.Num)

	}()

    }

    // Wait for goroutines to finish
    wg.Wait()
}
