package main

import (
	"context"
	"fmt"

	"go.idp.xyz/idp-gateway/internal/fabricpub/ports"
	rapplication "go.idp.xyz/idp-gateway/internal/routecompile/application"
	rdomain "go.idp.xyz/idp-gateway/internal/routecompile/domain"
	rports "go.idp.xyz/idp-gateway/internal/routecompile/ports"
)

// compileAdapter 把 fabricpub 的编译端口接到 routecompile。校验失败带 ports.ErrRefused。
type compileAdapter struct {
	validator rports.Validator
	tlsDir    string
}

func (a compileAdapter) ValidateAndCompile(ctx context.Context, specJSON []byte) (ports.CompiledBundle, error) {
	spec, err := rdomain.ParseSpec(specJSON)
	if err != nil {
		return ports.CompiledBundle{}, fmt.Errorf("%w: %s", ports.ErrRefused, oneLine(err.Error()))
	}
	result, err := (rapplication.Compiler{Validator: a.validator}).Compile(ctx, spec, "", "", a.tlsDir, "")
	if err != nil {
		return ports.CompiledBundle{}, fmt.Errorf("%w: %s", ports.ErrRefused, oneLine(err.Error()))
	}
	return ports.CompiledBundle{
		GatewayYAML:   result.Artifacts.GatewayYAML,
		PolicyJSON:    result.Artifacts.PolicyJSON,
		GatewaySHA256: result.Artifacts.GatewaySHA256,
		PolicyVersion: spec.Provider.PolicyVersion,
	}, nil
}
