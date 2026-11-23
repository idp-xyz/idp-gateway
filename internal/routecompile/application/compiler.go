// Package application 把编译、可选的原生校验和原子写文件串起来。
// 校验失败时两个输出文件都不写。
package application

import (
	"context"
	"errors"
	"os"
	"path/filepath"

	"go.idp.xyz/idp-gateway/internal/routecompile/domain"
	"go.idp.xyz/idp-gateway/internal/routecompile/ports"
)

// Compiler 编译一份规格。Validator 为空时不做原生校验。
type Compiler struct {
	Validator ports.Validator
}

// Result 是编译结果。NativeValidated 只在校验器跑过并且通过时为真。
type Result struct {
	Artifacts       domain.CompiledArtifacts
	NativeValidated bool
}

// Compile 编译出站规格。gatewayPath 或 policyPath 为空时不写对应的文件。
func (c Compiler) Compile(ctx context.Context, spec domain.CompileSpec, gatewayPath, policyPath, tlsDir, jwksFile string) (Result, error) {
	art, err := domain.Compile(spec)
	return c.finish(ctx, art, err, gatewayPath, policyPath, tlsDir, jwksFile)
}

// CompileIngress 编译入口规格。写文件和原生校验与 Compile 相同。
func (c Compiler) CompileIngress(ctx context.Context, spec domain.IngressSpec, gatewayPath, policyPath, tlsDir, jwksFile string) (Result, error) {
	art, err := domain.CompileIngress(spec)
	return c.finish(ctx, art, err, gatewayPath, policyPath, tlsDir, jwksFile)
}

// CompileAI 编译 AI 规格。写文件和原生校验与 Compile 相同。
func (c Compiler) CompileAI(ctx context.Context, spec domain.AISpec, gatewayPath, policyPath, tlsDir, jwksFile string) (Result, error) {
	art, err := domain.CompileAI(spec)
	return c.finish(ctx, art, err, gatewayPath, policyPath, tlsDir, jwksFile)
}

func (c Compiler) finish(ctx context.Context, art domain.CompiledArtifacts, compileErr error, gatewayPath, policyPath, tlsDir, jwksFile string) (Result, error) {
	if compileErr != nil {
		return Result{}, compileErr
	}
	validated := false
	if c.Validator != nil {
		if err := c.Validator.Validate(ctx, art.GatewayYAML, tlsDir, jwksFile); err != nil {
			if errors.Is(err, ports.ErrRefused) {
				return Result{}, &domain.Refusal{Issues: []domain.Issue{{Code: "NATIVE_VALIDATION_FAILED", Reason: err.Error()}}}
			}
			return Result{}, err
		}
		validated = true
	}
	if err := writeOutputs(gatewayPath, policyPath, art); err != nil {
		return Result{}, err
	}
	return Result{Artifacts: art, NativeValidated: validated}, nil
}

func writeOutputs(gatewayPath, policyPath string, art domain.CompiledArtifacts) error {
	if gatewayPath == "" && policyPath == "" {
		return nil
	}
	if gatewayPath != "" && gatewayPath == policyPath {
		return errors.New("output paths must be different files")
	}
	existed := false
	if gatewayPath != "" {
		if _, err := os.Stat(gatewayPath); err == nil {
			existed = true
		}
		if err := writeAtomic(gatewayPath, art.GatewayYAML); err != nil {
			return err
		}
	}
	if policyPath != "" {
		if err := writeAtomic(policyPath, art.PolicyJSON); err != nil {
			if gatewayPath != "" && !existed {
				os.Remove(gatewayPath)
			}
			return err
		}
	}
	return nil
}

func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".routecompile-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp, 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}
