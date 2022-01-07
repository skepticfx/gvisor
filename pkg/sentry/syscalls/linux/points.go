// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package linux

import (
	"gvisor.dev/gvisor/pkg/abi/linux"
	"gvisor.dev/gvisor/pkg/sentry/arch"
	"gvisor.dev/gvisor/pkg/sentry/kernel"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

func newOpen(t *kernel.Task, args arch.SyscallArguments) *pb.Open {
	info := &pb.Open{}
	addr := args[0].Pointer()
	if addr > 0 {
		path, err := t.CopyInString(addr, linux.PATH_MAX)
		if err == nil {
			info.Pathname = path
		}
	}
	return info
}

func OpenEnter(t *kernel.Task, _ uintptr, args arch.SyscallArguments) error {
	info := newOpen(t, args)
	return seccheck.Global.SendToCheckers(func(c seccheck.Checker) error {
		return c.Open(t, info)
	})
}

func OpenExit(t *kernel.Task, _ uintptr, args arch.SyscallArguments, rval uintptr, errno int) error {
	info := newOpen(t, args)
	info.Exit = &pb.Exit{
		Result:  int64(rval),
		Errorno: int64(errno),
	}
	return seccheck.Global.SendToCheckers(func(c seccheck.Checker) error {
		return c.Open(t, info)
	})
}

func newRead(args arch.SyscallArguments) *pb.Read {
	return &pb.Read{
		Fd:    int64(args[0].Int()),
		Count: uint64(args[2].SizeT()),
	}
}

func ReadEnter(t *kernel.Task, _ uintptr, args arch.SyscallArguments) error {
	info := newRead(args)
	return seccheck.Global.SendToCheckers(func(c seccheck.Checker) error {
		return c.Read(t, info)
	})
}

func ReadExit(t *kernel.Task, _ uintptr, args arch.SyscallArguments, rval uintptr, errno int) error {
	info := newRead(args)
	info.Exit = &pb.Exit{
		Result:  int64(rval),
		Errorno: int64(errno),
	}
	return seccheck.Global.SendToCheckers(func(c seccheck.Checker) error {
		return c.Read(t, info)
	})
}
