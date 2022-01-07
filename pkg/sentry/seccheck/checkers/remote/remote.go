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

// Package remote ...
package remote

import (
	"os"

	"gvisor.dev/gvisor/pkg/log"

	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
	"gvisor.dev/gvisor/pkg/cleanup"
	"gvisor.dev/gvisor/pkg/context"
	"gvisor.dev/gvisor/pkg/fd"
	"gvisor.dev/gvisor/pkg/sentry/seccheck"

	"google.golang.org/protobuf/types/known/anypb"
	pb "gvisor.dev/gvisor/pkg/sentry/seccheck/points/points_go_proto"
)

// TODO(fvoznika): Next steps:
// - Build test that sets up sentry and consumer (C++)
// - Convert existing points to proto
// - Fix startup hook
// - Build configuration

type Remote struct {
	seccheck.CheckerDefaults

	endpoint *fd.FD
}

var _ seccheck.Checker = (*Remote)(nil)

func Setup(path string) (*os.File, error) {
	socket, err := unix.Socket(unix.AF_UNIX, unix.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(socket), path)
	cu := cleanup.Make(func() {
		_ = f.Close()
	})
	defer cu.Clean()

	// TODO(fvoznika): add timeout
	addr := unix.SockaddrUnix{Name: path}
	if err := unix.Connect(int(f.Fd()), &addr); err != nil {
		return nil, err
	}
	cu.Release()
	return f, nil
}

func NewRemote(endpoint *fd.FD) *Remote {
	return &Remote{endpoint: endpoint}
}

// Header ...
//
// +marshal
type Header struct {
	MessageSize  uint32
	HeaderSize   uint16 // Doesn't include MessageSize.
	DroppedCount uint32 `marshal:"unaligned"`
}

// Note: Any requires writing the full type URL to the message. We're not
// memory bandwidth bound, but having an enum event type in the header to
// identify the proto type would reduce message size and speed up event dispatch
// in the consumer.
func (r *Remote) writeAny(any *anypb.Any) error {
	out, err := proto.Marshal(any)
	if err != nil {
		return err
	}
	const headerLength = 10
	hdr := Header{
		MessageSize: uint32(len(out) + headerLength),
		HeaderSize:  uint16(headerLength - 4),
	}
	var hdrOut [headerLength]byte
	hdr.MarshalUnsafe(hdrOut[:])

	// TODO(fvoznika): No blocking write. Count as dropped if write partial.
	_, err = unix.Writev(r.endpoint.FD(), [][]byte{hdrOut[:], out})
	return err
}

func (r *Remote) Open(ctx context.Context, info *pb.Open) error {
	log.Infof("Remote: open: %v", info)
	r.write(info)
	return nil
}

func (r *Remote) Read(ctx context.Context, info *pb.Read) error {
	log.Infof("Remote: read: %v", info)
	r.write(info)
	return nil
}

func (r *Remote) ContainerStart(ctx context.Context, info *pb.Start) error {
	log.Infof("Remote: container start: %v", info)
	r.write(info)
	return nil
}

func (r *Remote) write(msg proto.Message) {
	any, err := anypb.New(msg)
	if err != nil {
		log.Debugf("anypd.New(%+v): %v", msg, err)
		return
	}
	if err := r.writeAny(any); err != nil {
		log.Debugf("writeAny(%+v): %v", any, err)
		return
	}
	return
}
