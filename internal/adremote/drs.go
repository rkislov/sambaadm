package adremote

import (
	"context"
	"fmt"
	"github.com/oiweiwei/go-msrpc/dcerpc"
	"github.com/oiweiwei/go-msrpc/msrpc/drsr/drsuapi/v4"
	"github.com/oiweiwei/go-msrpc/msrpc/dtyp"
	"github.com/oiweiwei/go-msrpc/ndr"
	"unicode/utf16"
)

func (c *Client) drs(ctx context.Context, fn func(context.Context, drsuapi.DrsuapiClient, *drsuapi.Handle) error) error {
	ctx, cc, err := c.Connect(ctx)
	if err != nil {
		return err
	}
	defer cc.Close(ctx)
	client, err := drsuapi.NewDrsuapiClient(ctx, cc, dcerpc.WithSeal(), dcerpc.WithEndpoint("ncacn_ip_tcp:"))
	if err != nil {
		return err
	}
	data, err := ndr.Marshal(&drsuapi.ExtensionsInt{Flags: drsuapi.ExtStrongEncryption}, ndr.Opaque)
	if err != nil {
		return err
	}
	bind, err := client.Bind(ctx, &drsuapi.BindRequest{Client: &drsuapi.Extensions{Data: data}})
	if err != nil {
		return err
	}
	defer client.Unbind(ctx, &drsuapi.UnbindRequest{DRS: bind.DRS})
	return fn(ctx, client, bind.DRS)
}
func (c *Client) Neighbors(ctx context.Context) ([]*drsuapi.DSReplicationNeighbor, error) {
	var out []*drsuapi.DSReplicationNeighbor
	err := c.drs(ctx, func(ctx context.Context, client drsuapi.DrsuapiClient, h *drsuapi.Handle) error {
		resp, err := client.GetReplicationInfo(ctx, &drsuapi.GetReplicationInfoRequest{Handle: h, InVersion: 1, In: &drsuapi.MessageGetReplicationInfoRequest{Value: &drsuapi.MessageGetReplicationInfoRequest_V1{V1: &drsuapi.MessageGetReplicationInfoRequestV1{InfoType: 0}}}})
		if err != nil {
			return err
		}
		if resp.Out == nil {
			return fmt.Errorf("empty DRS response")
		}
		neighbors, ok := resp.Out.GetValue().(*drsuapi.DSReplicationNeighbors)
		if !ok {
			return fmt.Errorf("unexpected DRS response")
		}
		out = neighbors.Neighbor
		return nil
	})
	return out, err
}
func (c *Client) KCC(ctx context.Context) error {
	return c.drs(ctx, func(ctx context.Context, client drsuapi.DrsuapiClient, h *drsuapi.Handle) error {
		_, err := client.ExecuteKCC(ctx, &drsuapi.ExecuteKCCRequest{Handle: h, InVersion: 1, In: &drsuapi.MessageKCCExecute{Value: &drsuapi.MessageKCCExecute_V1{V1: &drsuapi.MessageKCCExecuteV1{}}}})
		return err
	})
}

func (c *Client) Sync(ctx context.Context, nc string, sourceGUID []byte) error {
	var guid dtyp.UUID
	if len(sourceGUID) != 16 {
		return fmt.Errorf("invalid source DSA GUID")
	}
	if err := ndr.Unmarshal(sourceGUID, &guid, ndr.Opaque); err != nil {
		return err
	}
	return c.drs(ctx, func(ctx context.Context, client drsuapi.DrsuapiClient, h *drsuapi.Handle) error {
		count := uint32(len(utf16.Encode([]rune(nc))))
		_, err := client.SyncReplica(ctx, &drsuapi.SyncReplicaRequest{Handle: h, Version: 1, Sync: &drsuapi.MessageReplicaSync{Value: &drsuapi.MessageReplicaSync_V1{V1: &drsuapi.MessageReplicaSyncV1{NC: &drsuapi.DSName{StringName: nc, NameLength: count, Length: 56 + 2*(count+1)}, DSASourceID: &guid, Options: 0x10}}}})
		return err
	})
}
