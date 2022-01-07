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

// Package seccheck defines a structure for dynamically-configured security
// checks in the sentry.
package seccheck

import (
	"sync/atomic"

	"gvisor.dev/gvisor/pkg/context"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
	"gvisor.dev/gvisor/pkg/sync"
)

// A Point represents a checkpoint, a point at which a security check occurs.
type Point uint

// PointX represents the checkpoint X.
const (
	PointClone Point = iota
	PointExecve
	PointExitNotifyParent
	PointContainerStart

	// Add new Points above this line.
	pointLengthBeforeSyscalls

	numPointBitmaskUint32s = (int(pointLengthBeforeSyscalls+pointLengthSyscalls)-1)/32 + 1
)

// A Checker performs security checks at checkpoints.
//
// Each Checker method X is called at checkpoint X; if the method may return a
// non-nil error and does so, it causes the checked operation to fail
// immediately (without calling subsequent Checkers) and return the error. The
// info argument contains information relevant to the check. The mask argument
// indicates what fields in info are valid; the mask should usually be a
// superset of fields requested by the Checker's corresponding CheckerReq, but
// may be missing requested fields in some cases (e.g. if the Checker is
// registered concurrently with invocations of checkpoints).
type Checker interface {
	Clone(ctx context.Context, mask CloneFieldSet, info CloneInfo) error
	Execve(ctx context.Context, mask ExecveFieldSet, info ExecveInfo) error
	ExitNotifyParent(ctx context.Context, mask ExitNotifyParentFieldSet, info ExitNotifyParentInfo) error

	// TODO(fvoznika): Replace with syscall enter/exit and move syscall parsing
	// here.
	Open(ctx context.Context, info *pb.Open) error
	Read(ctx context.Context, info *pb.Read) error

	ContainerStart(ctx context.Context, info *pb.Start) error
}

// CheckerDefaults may be embedded by implementations of Checker to obtain
// no-op implementations of Checker methods that may be explicitly overridden.
type CheckerDefaults struct{}

// Clone implements Checker.Clone.
func (CheckerDefaults) Clone(ctx context.Context, mask CloneFieldSet, info CloneInfo) error {
	return nil
}

// Execve implements Checker.Execve.
func (CheckerDefaults) Execve(ctx context.Context, mask ExecveFieldSet, info ExecveInfo) error {
	return nil
}

// ExitNotifyParent implements Checker.ExitNotifyParent.
func (CheckerDefaults) ExitNotifyParent(ctx context.Context, mask ExitNotifyParentFieldSet, info ExitNotifyParentInfo) error {
	return nil
}

func (CheckerDefaults) Open(context.Context, *pb.Open) error {
	return nil
}

func (CheckerDefaults) Read(context.Context, *pb.Read) error {
	return nil
}

func (CheckerDefaults) ContainerStart(context.Context, *pb.Start) error {
	return nil
}

// CheckerReq indicates what checkpoints a corresponding Checker runs at, and
// what information it requires at those checkpoints.
type CheckerReq struct {
	// Points are the set of checkpoints for which the corresponding Checker
	// must be called. Note that methods not specified in Points may still be
	// called; implementations of Checker may embed CheckerDefaults to obtain
	// no-op implementations of Checker methods.
	Points []Point

	// All of the following fields indicate what fields in the corresponding
	// XInfo struct will be requested at the corresponding checkpoint.
	Clone            CloneFields
	Execve           ExecveFields
	ExitNotifyParent ExitNotifyParentFields
}

// Global is the method receiver of all seccheck functions.
var Global State

// State is the type of global, and is separated out for testing.
type State struct {
	// registrationMu serializes all changes to the set of registered Checkers
	// for all checkpoints.
	registrationMu sync.Mutex

	// enabledPoints is a bitmask of checkpoints for which at least one Checker
	// is registered.
	//
	// enabledPoints is accessed using atomic memory operations. Mutation of
	// enabledPoints is serialized by registrationMu.
	enabledPoints [numPointBitmaskUint32s]uint32

	// registrationSeq supports store-free atomic reads of registeredCheckers.
	registrationSeq sync.SeqCount

	// checkers is the set of all registered Checkers in order of execution.
	//
	// checkers is accessed using instantiations of SeqAtomic functions.
	// Mutation of checkers is serialized by registrationMu.
	checkers []Checker

	// All of the following xReq variables indicate what fields in the
	// corresponding XInfo struct have been requested by any registered
	// checker, are accessed using atomic memory operations, and are mutated
	// with registrationMu locked.
	cloneReq            CloneFieldSet
	execveReq           ExecveFieldSet
	exitNotifyParentReq ExitNotifyParentFieldSet
}

// AppendChecker registers the given Checker to execute at checkpoints. The
// Checker will execute after all previously-registered Checkers, and only if
// those Checkers return a nil error.
func (s *State) AppendChecker(c Checker, req *CheckerReq) {
	s.registrationMu.Lock()
	defer s.registrationMu.Unlock()

	s.cloneReq.AddFieldsLoadable(req.Clone)
	s.execveReq.AddFieldsLoadable(req.Execve)
	s.exitNotifyParentReq.AddFieldsLoadable(req.ExitNotifyParent)

	s.appendCheckerLocked(c)
	for _, p := range req.Points {
		word, bit := p/32, p%32
		atomic.StoreUint32(&s.enabledPoints[word], s.enabledPoints[word]|(uint32(1)<<bit))
	}
}

// Enabled returns true if any Checker is registered for the given checkpoint.
func (s *State) Enabled(p Point) bool {
	word, bit := p/32, p%32
	if int(word) >= len(s.enabledPoints) {
		return false
	}
	return atomic.LoadUint32(&s.enabledPoints[word])&(uint32(1)<<bit) != 0
}

func (s *State) SyscallEnabledEnter(sysno uintptr) bool {
	pt := Point(sysno)*2 + pointLengthBeforeSyscalls
	return s.Enabled(pt)
}

func (s *State) SyscallEnabledExit(sysno uintptr) bool {
	pt := Point(sysno)*2 + 1 + pointLengthBeforeSyscalls
	return s.Enabled(pt)
}

func (s *State) getCheckers() []Checker {
	return SeqAtomicLoadCheckerSlice(&s.registrationSeq, &s.checkers)
}

// Preconditions: s.registrationMu must be locked.
func (s *State) appendCheckerLocked(c Checker) {
	s.registrationSeq.BeginWrite()
	s.checkers = append(s.checkers, c)
	s.registrationSeq.EndWrite()
}

func (s *State) SendToCheckers(fn func(c Checker) error) error {
	for _, c := range s.getCheckers() {
		if err := fn(c); err != nil {
			return err
		}
	}
	return nil
}
