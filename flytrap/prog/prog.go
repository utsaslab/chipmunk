// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"github.com/google/syzkaller/pkg/log"
	"math"
)

type Prog struct {
	Target   *Target
	Calls    []*Call
	Comments []string
	Name     string `default:""`
}

type Call struct {
	Meta    *Syscall
	Args    []Arg
	Ret     *ResultArg
	Comment string
}

func (p *Prog) Filter() bool {
	//if p.hasMissingFileResources() {
	//	return false
	//}
	for _, call := range p.Calls {
		for _, arg := range call.Args {
			switch arg.Type().(type) {
			case *ResourceType:
				log.Logf(0, "ARG: %v", arg)
				switch a := arg.(type) {
				case *ConstArg:
					log.Logf(0, "FILTERING PROG: %v", string(p.Serialize()))
					return true
				case *ResultArg:
					log.Logf(0, "RESULT ARG: %v", a.Val)
					if a.Val == math.MaxUint64 {
						log.Logf(0, "FILTERING PROG: %v", string(p.Serialize()))
						return true
					}
				}
			}
		}
	}
	return false
}

func (p *Prog) hasMissingFileResources() bool {
	fMap := make(map[string]bool)
	for _, call := range p.Calls {
		files, directories := p.getFiles(call, fMap)
		for file := range files {
			if _, ok := fMap[file]; !ok {
				return true
			}
		}
		for dir := range directories {
			if _, ok := fMap[dir]; !ok {
				return true
			}
		}
	}
	return false
}

func (p *Prog) InsertMissingFileResources() {
	log.Logf(0, "BEFORE INSERTING RESOURCES: %v", string(p.Serialize()))
	fMap := make(map[string]bool)
	openCalls := make([]*Call, 0)
	for i := range p.Calls {
		files, directories := p.getFiles(p.Calls[i], fMap)
		log.Logf(0, "files: %v, directories: %v", files, directories)
		for file, arg := range files {
			if _, ok := fMap[file]; !ok {
				openCalls = append(openCalls, p.genOpen(arg))
				fMap[file] = true
			}
		}
		for dir, arg := range directories {
			if _, ok := fMap[dir]; !ok {
				openCalls = append(openCalls, p.genMkdir(arg))
				fMap[dir] = true
			}
		}
	}
	p.Calls = append(openCalls, p.Calls...)
	log.Logf(0, "AFTER INSERTING RESOURCES: %v", string(p.Serialize()))
}

func (p *Prog) genOpen(f Arg) *Call {
	meta := p.Target.SyscallMap["open"]
	log.Logf(0, "META: %v", meta)
	c := &Call{
		Meta: meta,
		Ret:  MakeReturnArg(meta.Ret),
	}
	c.Args = make([]Arg, len(meta.Args))
	c.Args[0] = f
	switch mode := meta.Args[1].Type.(type) {
	case *FlagsType:
		c.Args[1] = MakeConstArg(mode, meta.Args[1].Direction, p.Target.ConstMap["O_RDWR"]|p.Target.ConstMap["O_CREAT"])
	}
	switch mode := meta.Args[1].Type.(type) {
	case *FlagsType:
		c.Args[2] = MakeConstArg(mode, meta.Args[1].Direction, p.Target.ConstMap["S_IRUSR"]|p.Target.ConstMap["S_IRGRP"])
	}
	p.Target.assignSizesCall(c)
	return c
}

func (p *Prog) genMkdir(f Arg) *Call {
	meta := p.Target.SyscallMap["mkdir"]
	log.Logf(0, "META: %v", meta)
	c := &Call{
		Meta: meta,
		Ret:  MakeReturnArg(meta.Ret),
	}
	c.Args = make([]Arg, len(meta.Args))
	c.Args[0] = f
	switch mode := meta.Args[1].Type.(type) {
	case *FlagsType:
		c.Args[1] = MakeConstArg(mode, meta.Args[1].Direction, p.Target.ConstMap["S_IRUSR"]|p.Target.ConstMap["S_IRGRP"])
	}
	p.Target.assignSizesCall(c)
	return c
}

func (p *Prog) getFiles(call *Call, fMap map[string]bool) (map[string]Arg, map[string]Arg) {
	files := make(map[string]Arg, 0)
	dirs := make(map[string]Arg, 0)
	log.Logf(0, "CALL NAME: %v", call.Meta.CallName)
	switch call.Meta.CallName {
	case "rename":
		switch a := call.Args[0].(type) {
		case *PointerArg:
			switch b := a.Res.(type) {
			case *DataArg:
				files[string(b.data)] = call.Args[0]
			}
		}
		switch a := call.Args[1].(type) {
		case *PointerArg:
			switch b := a.Res.(type) {
			case *DataArg:
				files[string(b.data)] = call.Args[1]
			}
		}
	case "open", "mkdir":
		switch a := call.Args[0].(type) {
		case *PointerArg:
			switch b := a.Res.(type) {
			case *DataArg:
				fMap[string(b.data)] = true
			}
		}
	case "rmdir":
		switch a := call.Args[0].(type) {
		case *PointerArg:
			switch b := a.Res.(type) {
			case *DataArg:
				dirs[string(b.data)] = a
			}
		}
	case "symlink", "chmod", "lchmod", "unlink", "readlink":
		log.Logf(0, "CALL ARG: %v", call.Args[0])
		switch a := call.Args[0].(type) {
		case *PointerArg:
			switch b := a.Res.(type) {
			case *DataArg:
				files[string(b.data)] = call.Args[0]
			}
		}
	}
	return files, dirs
}

type Arg interface {
	Type() Type
	Dir() Dir
	Size() uint64

	validate(ctx *validCtx) error
	serialize(ctx *serializer)
}

type ArgCommon struct {
	ref Ref
	dir Dir
}

func (arg ArgCommon) Type() Type {
	if arg.ref == 0 {
		panic("broken type ref")
	}
	return typeRefs.Load().([]Type)[arg.ref]
}

func (arg *ArgCommon) Dir() Dir {
	return arg.dir
}

// Used for ConstType, IntType, FlagsType, LenType, ProcType and CsumType.
type ConstArg struct {
	ArgCommon
	Val uint64
}

func MakeConstArg(t Type, dir Dir, v uint64) *ConstArg {
	return &ConstArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, Val: v}
}

func (arg *ConstArg) Size() uint64 {
	return arg.Type().Size()
}

// Value returns value and pid stride.
func (arg *ConstArg) Value() (uint64, uint64) {
	switch typ := (*arg).Type().(type) {
	case *IntType:
		return arg.Val, 0
	case *ConstType:
		return arg.Val, 0
	case *FlagsType:
		return arg.Val, 0
	case *LenType:
		return arg.Val, 0
	case *ResourceType:
		return arg.Val, 0
	case *CsumType:
		// Checksums are computed dynamically in executor.
		return 0, 0
	case *ProcType:
		if arg.Val == procDefaultValue {
			return 0, 0
		}
		return typ.ValuesStart + arg.Val, typ.ValuesPerProc
	default:
		panic(fmt.Sprintf("unknown ConstArg type %#v", typ))
	}
}

// Used for PtrType and VmaType.
type PointerArg struct {
	ArgCommon
	Address uint64
	VmaSize uint64 // size of the referenced region for vma args
	Res     Arg    // pointee (nil for vma)
}

func MakePointerArg(t Type, dir Dir, addr uint64, data Arg) *PointerArg {
	if data == nil {
		panic("nil pointer data arg")
	}
	return &PointerArg{
		ArgCommon: ArgCommon{ref: t.ref(), dir: DirIn}, // pointers are always in
		Address:   addr,
		Res:       data,
	}
}

func MakeVmaPointerArg(t Type, dir Dir, addr, size uint64) *PointerArg {
	if addr%1024 != 0 {
		panic("unaligned vma address")
	}
	return &PointerArg{
		ArgCommon: ArgCommon{ref: t.ref(), dir: dir},
		Address:   addr,
		VmaSize:   size,
	}
}

func MakeSpecialPointerArg(t Type, dir Dir, index uint64) *PointerArg {
	if index >= maxSpecialPointers {
		panic("bad special pointer index")
	}
	if _, ok := t.(*PtrType); ok {
		dir = DirIn // pointers are always in
	}
	return &PointerArg{
		ArgCommon: ArgCommon{ref: t.ref(), dir: dir},
		Address:   -index,
	}
}

func (arg *PointerArg) Size() uint64 {
	return arg.Type().Size()
}

func (arg *PointerArg) IsSpecial() bool {
	return arg.VmaSize == 0 && arg.Res == nil && -arg.Address < maxSpecialPointers
}

func (target *Target) PhysicalAddr(arg *PointerArg) uint64 {
	if arg.IsSpecial() {
		return target.SpecialPointers[-arg.Address]
	}
	return target.DataOffset + arg.Address
}

// Used for BufferType.
type DataArg struct {
	ArgCommon
	data []byte // for in/inout args
	size uint64 // for out Args
}

func MakeDataArg(t Type, dir Dir, data []byte) *DataArg {
	if dir == DirOut {
		panic("non-empty output data arg")
	}
	return &DataArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, data: append([]byte{}, data...)}
}

func MakeOutDataArg(t Type, dir Dir, size uint64) *DataArg {
	if dir != DirOut {
		panic("empty input data arg")
	}
	return &DataArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, size: size}
}

func (arg *DataArg) Size() uint64 {
	if len(arg.data) != 0 {
		return uint64(len(arg.data))
	}
	return arg.size
}

func (arg *DataArg) Data() []byte {
	if arg.Dir() == DirOut {
		panic("getting data of output data arg")
	}
	return arg.data
}

func (arg *DataArg) SetData(data []byte) {
	if arg.Dir() == DirOut {
		panic("setting data of output data arg")
	}
	arg.data = append([]byte{}, data...)
}

// Used for StructType and ArrayType.
// Logical group of args (struct or array).
type GroupArg struct {
	ArgCommon
	Inner []Arg
}

func MakeGroupArg(t Type, dir Dir, inner []Arg) *GroupArg {
	return &GroupArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, Inner: inner}
}

func (arg *GroupArg) Size() uint64 {
	typ0 := arg.Type()
	if !typ0.Varlen() {
		return typ0.Size()
	}
	switch typ := typ0.(type) {
	case *StructType:
		var size uint64
		for _, fld := range arg.Inner {
			size += fld.Size()
		}
		if typ.AlignAttr != 0 && size%typ.AlignAttr != 0 {
			size += typ.AlignAttr - size%typ.AlignAttr
		}
		return size
	case *ArrayType:
		var size uint64
		for _, elem := range arg.Inner {
			size += elem.Size()
		}
		return size
	default:
		panic(fmt.Sprintf("bad group arg type %v", typ))
	}
}

func (arg *GroupArg) fixedInnerSize() bool {
	switch typ := arg.Type().(type) {
	case *StructType:
		return true
	case *ArrayType:
		return typ.Kind == ArrayRangeLen && typ.RangeBegin == typ.RangeEnd
	default:
		panic(fmt.Sprintf("bad group arg type %v", typ))
	}
}

// Used for UnionType.
type UnionArg struct {
	ArgCommon
	Option Arg
	Index  int // Index of the selected option in the union type.
}

func MakeUnionArg(t Type, dir Dir, opt Arg, index int) *UnionArg {
	return &UnionArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, Option: opt, Index: index}
}

func (arg *UnionArg) Size() uint64 {
	if !arg.Type().Varlen() {
		return arg.Type().Size()
	}
	return arg.Option.Size()
}

// Used for ResourceType.
// This is the only argument that can be used as syscall return value.
// Either holds constant value or reference another ResultArg.
type ResultArg struct {
	ArgCommon
	Res   *ResultArg          // reference to arg which we use
	OpDiv uint64              // divide result (executed before OpAdd)
	OpAdd uint64              // add to result
	Val   uint64              // value used if Res is nil
	uses  map[*ResultArg]bool // args that use this arg
}

func MakeResultArg(t Type, dir Dir, r *ResultArg, v uint64) *ResultArg {
	arg := &ResultArg{ArgCommon: ArgCommon{ref: t.ref(), dir: dir}, Res: r, Val: v}
	if r == nil {
		return arg
	}
	if r.uses == nil {
		r.uses = make(map[*ResultArg]bool)
	}
	r.uses[arg] = true
	return arg
}

func MakeReturnArg(t Type) *ResultArg {
	if t == nil {
		return nil
	}
	return &ResultArg{ArgCommon: ArgCommon{ref: t.ref(), dir: DirOut}}
}

func (arg *ResultArg) Size() uint64 {
	return arg.Type().Size()
}

// Returns inner arg for pointer args.
func InnerArg(arg Arg) Arg {
	if _, ok := arg.Type().(*PtrType); ok {
		res := arg.(*PointerArg).Res
		if res == nil {
			return nil
		}
		return InnerArg(res)
	}
	return arg // Not a pointer.
}

func isDefault(arg Arg) bool {
	return arg.Type().isDefaultArg(arg)
}

func (p *Prog) insertBefore(c *Call, calls []*Call) {
	idx := 0
	for ; idx < len(p.Calls); idx++ {
		if p.Calls[idx] == c {
			break
		}
	}
	var newCalls []*Call
	newCalls = append(newCalls, p.Calls[:idx]...)
	newCalls = append(newCalls, calls...)
	if idx < len(p.Calls) {
		newCalls = append(newCalls, p.Calls[idx])
		newCalls = append(newCalls, p.Calls[idx+1:]...)
	}
	p.Calls = newCalls
}

// replaceArg replaces arg with arg1 in a program.
func replaceArg(arg, arg1 Arg) {
	switch a := arg.(type) {
	case *ConstArg:
		*a = *arg1.(*ConstArg)
	case *ResultArg:
		replaceResultArg(a, arg1.(*ResultArg))
	case *PointerArg:
		*a = *arg1.(*PointerArg)
	case *UnionArg:
		*a = *arg1.(*UnionArg)
	case *DataArg:
		*a = *arg1.(*DataArg)
	case *GroupArg:
		a1 := arg1.(*GroupArg)
		if len(a.Inner) != len(a1.Inner) {
			panic(fmt.Sprintf("replaceArg: group fields don't match: %v/%v",
				len(a.Inner), len(a1.Inner)))
		}
		a.ArgCommon = a1.ArgCommon
		for i := range a.Inner {
			replaceArg(a.Inner[i], a1.Inner[i])
		}
	default:
		panic(fmt.Sprintf("replaceArg: bad arg kind %#v", arg))
	}
}

func replaceResultArg(arg, arg1 *ResultArg) {
	// Remove link from `a.Res` to `arg`.
	if arg.Res != nil {
		delete(arg.Res.uses, arg)
	}
	// Copy all fields from `arg1` to `arg` except for the list of args that use `arg`.
	uses := arg.uses
	*arg = *arg1
	arg.uses = uses
	// Make the link in `arg.Res` (which is now `Res` of `arg1`) to point to `arg` instead of `arg1`.
	if arg.Res != nil {
		resUses := arg.Res.uses
		delete(resUses, arg1)
		resUses[arg] = true
	}
}

// removeArg removes all references to/from arg0 from a program.
func removeArg(arg0 Arg) {
	ForeachSubArg(arg0, func(arg Arg, ctx *ArgCtx) {
		a, ok := arg.(*ResultArg)
		if !ok {
			return
		}
		if a.Res != nil {
			uses := a.Res.uses
			if !uses[a] {
				panic("broken tree")
			}
			delete(uses, a)
		}
		for arg1 := range a.uses {
			arg2 := arg1.Type().DefaultArg(arg1.Dir()).(*ResultArg)
			replaceResultArg(arg1, arg2)
		}
	})
}

// removeCall removes call idx from p.
func (p *Prog) removeCall(idx int) {
	c := p.Calls[idx]
	for _, arg := range c.Args {
		removeArg(arg)
	}
	if c.Ret != nil {
		removeArg(c.Ret)
	}
	copy(p.Calls[idx:], p.Calls[idx+1:])
	p.Calls = p.Calls[:len(p.Calls)-1]
}

func (p *Prog) sanitizeFix() {
	if err := p.sanitize(true); err != nil {
		panic(err)
	}
}

func (p *Prog) sanitize(fix bool) error {
	for _, c := range p.Calls {
		if err := p.Target.sanitize(c, fix); err != nil {
			return err
		}
	}
	return nil
}
