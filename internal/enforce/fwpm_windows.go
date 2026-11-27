package enforce

import (
	"errors"
	"fmt"
	"net/netip"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Привязки к Windows Filtering Platform (fwpuclnt.dll) — ровно то, что нужно
// исполнителю: сессия, поставщик, подуровень, фильтры с условиями «приложение»,
// «пакет Store», «локальный адрес», «удалённый адрес и порт», «петля». Структуры повторяют fwptypes.h и fwpmtypes.h для
// 64-битной Windows (amd64 и arm64); размеры сверяются при сборке (ниже).

var (
	fwpuclnt                 = windows.NewLazySystemDLL("fwpuclnt.dll")
	procEngineOpen           = fwpuclnt.NewProc("FwpmEngineOpen0")
	procEngineClose          = fwpuclnt.NewProc("FwpmEngineClose0")
	procProviderAdd          = fwpuclnt.NewProc("FwpmProviderAdd0")
	procProviderDeleteByKey  = fwpuclnt.NewProc("FwpmProviderDeleteByKey0")
	procSubLayerAdd          = fwpuclnt.NewProc("FwpmSubLayerAdd0")
	procSubLayerDeleteByKey  = fwpuclnt.NewProc("FwpmSubLayerDeleteByKey0")
	procSubLayerGetByKey     = fwpuclnt.NewProc("FwpmSubLayerGetByKey0")
	procFilterAdd            = fwpuclnt.NewProc("FwpmFilterAdd0")
	procFilterDeleteByKey    = fwpuclnt.NewProc("FwpmFilterDeleteByKey0")
	procFilterGetByKey       = fwpuclnt.NewProc("FwpmFilterGetByKey0")
	procGetAppIDFromFileName = fwpuclnt.NewProc("FwpmGetAppIdFromFileName0")
	procFreeMemory           = fwpuclnt.NewProc("FwpmFreeMemory0")

	procDeriveAppContainerSid = windows.NewLazySystemDLL("userenv.dll").NewProc("DeriveAppContainerSidFromAppContainerName")
)

// Уровни и поля (fwpmu.h).
var (
	layerConnectV4 = guid(0xc38d57d1, 0x05a7, 0x4c33, 0x90, 0x4f, 0x7f, 0xbc, 0xee, 0xe6, 0x0e, 0x82)
	layerConnectV6 = guid(0x4a72393b, 0x319f, 0x44bc, 0x84, 0xc3, 0xba, 0x54, 0xdc, 0xb3, 0xb6, 0xb4)
	layerAcceptV4  = guid(0xe1cd9fe7, 0xf4b5, 0x4273, 0x96, 0xc0, 0x59, 0x2e, 0x48, 0x7b, 0x86, 0x50)
	layerAcceptV6  = guid(0xa3b42c97, 0x9f04, 0x4672, 0xb8, 0x7e, 0xce, 0xe9, 0xc4, 0x83, 0x25, 0x7f)

	conditionAppID      = guid(0xd78e1e87, 0x8644, 0x4ea5, 0x94, 0x37, 0xd8, 0x09, 0xec, 0xef, 0xc9, 0x71)
	conditionPackageID  = guid(0x71bc78fa, 0xf17c, 0x4997, 0xa6, 0x02, 0x6a, 0xbb, 0x26, 0x1f, 0x35, 0x1c)
	conditionLocalAddr  = guid(0xd9ee00de, 0xc1ef, 0x4617, 0xbf, 0xe3, 0xff, 0xd8, 0xf5, 0xa0, 0x89, 0x57)
	conditionRemoteAddr = guid(0xb235ae9a, 0x1d64, 0x49b8, 0xa4, 0x4c, 0x5f, 0xf3, 0xd9, 0x09, 0x50, 0x45)
	conditionRemotePort = guid(0xc35a604d, 0xd22b, 0x4e1a, 0x91, 0xb4, 0x68, 0xf6, 0x74, 0xee, 0x67, 0x4b)
	conditionFlags      = guid(0x632ce23b, 0x5167, 0x435c, 0x86, 0xd7, 0xe9, 0x03, 0x68, 0x4a, 0xa8, 0x0c)
)

func guid(d1 uint32, d2, d3 uint16, d4 ...byte) windows.GUID {
	g := windows.GUID{Data1: d1, Data2: d2, Data3: d3}
	copy(g.Data4[:], d4)
	return g
}

// Константы fwptypes.h и fwpmtypes.h.
const (
	rpcAuthnWinNT = 10

	sessionFlagDynamic      = 0x1
	providerFlagPersistent  = 0x1
	sublayerFlagPersistent  = 0x1
	filterFlagPersistent    = 0x1
	filterFlagBootTime      = 0x2
	filterFlagClearAction   = 0x8 // FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT: жёсткое действие
	conditionFlagIsLoopback = 0x1

	dataUint8       = 1
	dataUint16      = 2
	dataUint32      = 3
	dataByteArray16 = 11
	dataByteBlob    = 12
	dataSID         = 13

	matchEqual       = 0
	matchFlagsAllSet = 6

	actionBlock  = 0x1001
	actionPermit = 0x1002
)

type fwpmDisplayData0 struct {
	name        *uint16
	description *uint16
}

type fwpByteBlob struct {
	size uint32
	data *byte
}

// fwpValue0 и fwpConditionValue0 — тип и объединение из 8 байт: число лежит
// в нём самом, остальное — указателем.
type fwpValue0 struct {
	typ   uint32
	value uintptr
}

type fwpmSession0 struct {
	sessionKey           windows.GUID
	displayData          fwpmDisplayData0
	flags                uint32
	txnWaitTimeoutInMSec uint32
	processID            uint32
	sid                  *windows.SID
	username             *uint16
	kernelMode           int32
}

type fwpmProvider0 struct {
	providerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerData fwpByteBlob
	serviceName  *uint16
}

type fwpmSublayer0 struct {
	subLayerKey  windows.GUID
	displayData  fwpmDisplayData0
	flags        uint32
	providerKey  *windows.GUID
	providerData fwpByteBlob
	weight       uint16
}

type fwpmFilterCondition0 struct {
	fieldKey       windows.GUID
	matchType      uint32
	conditionValue fwpValue0
}

type fwpmAction0 struct {
	typ        uint32
	filterType windows.GUID
}

type fwpmFilter0 struct {
	filterKey           windows.GUID
	displayData         fwpmDisplayData0
	flags               uint32
	providerKey         *windows.GUID
	providerData        fwpByteBlob
	layerKey            windows.GUID
	subLayerKey         windows.GUID
	weight              fwpValue0
	numFilterConditions uint32
	filterCondition     *fwpmFilterCondition0
	action              fwpmAction0
	providerContextKey  [2]uint64 // объединение UINT64 и GUID: выравнивание 8
	reserved            *windows.GUID
	filterID            uint64
	effectiveWeight     fwpValue0
}

// Размеры структур на 64-битной Windows: разойдутся с fwpmtypes.h — не соберётся.
var (
	_ [unsafe.Sizeof(fwpmSession0{}) - 72]byte
	_ [72 - unsafe.Sizeof(fwpmSession0{})]byte
	_ [unsafe.Sizeof(fwpmProvider0{}) - 64]byte
	_ [64 - unsafe.Sizeof(fwpmProvider0{})]byte
	_ [unsafe.Sizeof(fwpmSublayer0{}) - 72]byte
	_ [72 - unsafe.Sizeof(fwpmSublayer0{})]byte
	_ [unsafe.Sizeof(fwpmFilterCondition0{}) - 40]byte
	_ [40 - unsafe.Sizeof(fwpmFilterCondition0{})]byte
	_ [unsafe.Sizeof(fwpmFilter0{}) - 200]byte
	_ [200 - unsafe.Sizeof(fwpmFilter0{})]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.action) - 128]byte
	_ [128 - unsafe.Offsetof(fwpmFilter0{}.action)]byte
	_ [unsafe.Offsetof(fwpmFilter0{}.providerContextKey) - 152]byte
	_ [152 - unsafe.Offsetof(fwpmFilter0{}.providerContextKey)]byte
)

// result — код возврата функции WFP: 0 — успех, иначе FWP_E_* или ошибка Win32.
// Код — DWORD, старшая половина регистра не определена: на ARM64 FWP_E_*
// приходят с расширенным знаком (0xffffffff80320009), и без uint32 сравнение
// с fwpAlreadyExists не срабатывало бы.
func result(r uintptr) error {
	if uint32(r) == 0 {
		return nil
	}
	return windows.Errno(uint32(r))
}

// fwpEngine — открытая сессия WFP.
type fwpEngine struct{ h windows.Handle }

// openEngine открывает сессию. Объекты динамической сессии Windows снимает
// сама, когда сессия закрыта или процесс завершился.
func openEngine(name string, dynamic bool) (*fwpEngine, error) {
	s := &fwpmSession0{displayData: display(name, "")}
	if dynamic {
		s.flags = sessionFlagDynamic
	}
	var h windows.Handle
	r, _, _ := procEngineOpen.Call(0, rpcAuthnWinNT, 0, uintptr(unsafe.Pointer(s)), uintptr(unsafe.Pointer(&h)))
	runtime.KeepAlive(s)
	if err := result(r); err != nil {
		return nil, err
	}
	return &fwpEngine{h}, nil
}

func (e *fwpEngine) close() error {
	r, _, _ := procEngineClose.Call(uintptr(e.h))
	return result(r)
}

func (e *fwpEngine) addProvider(id windows.GUID, name, description string) error {
	p := &fwpmProvider0{providerKey: id, displayData: display(name, description), flags: providerFlagPersistent}
	r, _, _ := procProviderAdd.Call(uintptr(e.h), uintptr(unsafe.Pointer(p)), 0)
	runtime.KeepAlive(p)
	return result(r)
}

func (e *fwpEngine) deleteProvider(id windows.GUID) error {
	r, _, _ := procProviderDeleteByKey.Call(uintptr(e.h), uintptr(unsafe.Pointer(&id)))
	return result(r)
}

func (e *fwpEngine) addSublayer(id, provider windows.GUID, name, description string, weight uint16) error {
	sl := &fwpmSublayer0{subLayerKey: id, displayData: display(name, description), flags: sublayerFlagPersistent,
		providerKey: &provider, weight: weight}
	r, _, _ := procSubLayerAdd.Call(uintptr(e.h), uintptr(unsafe.Pointer(sl)), 0)
	runtime.KeepAlive(sl)
	return result(r)
}

func (e *fwpEngine) deleteSublayer(id windows.GUID) error {
	r, _, _ := procSubLayerDeleteByKey.Call(uintptr(e.h), uintptr(unsafe.Pointer(&id)))
	return result(r)
}

// hasSublayer — подуровень на месте; не найден — false без ошибки.
func (e *fwpEngine) hasSublayer(id windows.GUID) (bool, error) {
	var sl *fwpmSublayer0
	r, _, _ := procSubLayerGetByKey.Call(uintptr(e.h), uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&sl)))
	return e.found(result(r), unsafe.Pointer(&sl), fwpSublayerNotFound)
}

// hasFilter — фильтр на месте; не найден — false без ошибки.
func (e *fwpEngine) hasFilter(id windows.GUID) (bool, error) {
	var f *fwpmFilter0
	r, _, _ := procFilterGetByKey.Call(uintptr(e.h), uintptr(unsafe.Pointer(&id)), uintptr(unsafe.Pointer(&f)))
	return e.found(result(r), unsafe.Pointer(&f), fwpFilterNotFound)
}

func (e *fwpEngine) found(err error, mem unsafe.Pointer, notFound windows.Errno) (bool, error) {
	switch {
	case errors.Is(err, notFound):
		return false, nil
	case err != nil:
		return false, err
	}
	procFreeMemory.Call(uintptr(mem))
	return true, nil
}

// fwFilter — фильтр в терминах исполнителя: условия складываются по «и».
type fwFilter struct {
	id, layer, sublayer, provider windows.GUID // нулевые sublayer и provider — подуровень по умолчанию, без поставщика
	name                          string
	weight                        uint8
	permit                        bool
	persistent, boot              bool
	hard                          bool // жёсткое: нижние подуровни его не переиграют
	appID                         []byte         // ALE_APP_ID == appID, если задан
	sid                           []byte         // ALE_PACKAGE_ID == sid (пакет Store), если задан
	local                         netip.Addr     // IP_LOCAL_ADDRESS == local, если задан
	remote                        netip.AddrPort // IP_REMOTE_ADDRESS, если задан, и IP_REMOTE_PORT, если не 0
	loopback                      bool           // соединение с самой машиной
}

// filterMem — фильтр и всё, на что он указывает, одним объектом в куче Go.
// Значения условий WFP держит в объединении — сборщик мусора таких указателей
// не видит, поэтому они указывают только внутрь этого же объекта: он жив, пока
// жив сам фильтр, и в куче Go не двигается.
type filterMem struct {
	filter   fwpmFilter0
	conds    [5]fwpmFilterCondition0
	blob     fwpByteBlob
	local6   [16]byte
	remote6  [16]byte
	app, sid []byte
	name     *uint16
	prov     windows.GUID
}

func (e *fwpEngine) addFilter(f fwFilter) error {
	m := new(filterMem)
	n := 0
	cond := func(field windows.GUID, match, typ uint32, value uintptr) {
		m.conds[n] = fwpmFilterCondition0{fieldKey: field, matchType: match, conditionValue: fwpValue0{typ: typ, value: value}}
		n++
	}
	if len(f.appID) > 0 {
		m.app = append([]byte(nil), f.appID...)
		m.blob = fwpByteBlob{size: uint32(len(m.app)), data: &m.app[0]}
		cond(conditionAppID, matchEqual, dataByteBlob, uintptr(unsafe.Pointer(&m.blob)))
	}
	if len(f.sid) > 0 {
		m.sid = append([]byte(nil), f.sid...)
		cond(conditionPackageID, matchEqual, dataSID, uintptr(unsafe.Pointer(&m.sid[0])))
	}
	// Адрес IPv4 — числом в порядке байт этой машины, IPv6 — 16 байтами.
	if a := f.local; a.Is4() {
		cond(conditionLocalAddr, matchEqual, dataUint32, uintptr(v4(a)))
	} else if a.Is6() {
		m.local6 = a.As16()
		cond(conditionLocalAddr, matchEqual, dataByteArray16, uintptr(unsafe.Pointer(&m.local6)))
	}
	if a := f.remote.Addr(); a.Is4() {
		cond(conditionRemoteAddr, matchEqual, dataUint32, uintptr(v4(a)))
	} else if a.Is6() {
		m.remote6 = a.As16()
		cond(conditionRemoteAddr, matchEqual, dataByteArray16, uintptr(unsafe.Pointer(&m.remote6)))
	}
	if f.remote.Port() != 0 {
		cond(conditionRemotePort, matchEqual, dataUint16, uintptr(f.remote.Port()))
	}
	if f.loopback {
		cond(conditionFlags, matchFlagsAllSet, dataUint32, conditionFlagIsLoopback)
	}
	m.name, _ = windows.UTF16PtrFromString(f.name)
	m.filter = fwpmFilter0{
		filterKey:           f.id,
		displayData:         fwpmDisplayData0{name: m.name},
		layerKey:            f.layer,
		subLayerKey:         f.sublayer,
		weight:              fwpValue0{typ: dataUint8, value: uintptr(f.weight)},
		numFilterConditions: uint32(n),
		action:              fwpmAction0{typ: actionBlock},
	}
	if n > 0 {
		m.filter.filterCondition = &m.conds[0]
	}
	if f.provider != (windows.GUID{}) {
		m.prov = f.provider
		m.filter.providerKey = &m.prov
	}
	if f.permit {
		m.filter.action.typ = actionPermit
	}
	if f.persistent {
		m.filter.flags |= filterFlagPersistent
	}
	if f.boot {
		m.filter.flags |= filterFlagBootTime
	}
	if f.hard {
		m.filter.flags |= filterFlagClearAction
	}
	var id uint64
	r, _, _ := procFilterAdd.Call(uintptr(e.h), uintptr(unsafe.Pointer(&m.filter)), 0, uintptr(unsafe.Pointer(&id)))
	runtime.KeepAlive(m)
	return result(r)
}

func v4(a netip.Addr) uint32 {
	b := a.As4()
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

func (e *fwpEngine) deleteFilter(id windows.GUID) error {
	r, _, _ := procFilterDeleteByKey.Call(uintptr(e.h), uintptr(unsafe.Pointer(&id)))
	return result(r)
}

// appIDOf — идентификатор приложения для WFP: путь к файлу в виде пути
// устройства. Файл должен существовать.
func appIDOf(path string) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, err
	}
	var blob *fwpByteBlob
	r, _, _ := procGetAppIDFromFileName.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&blob)))
	if err := result(r); err != nil {
		return nil, err
	}
	defer procFreeMemory.Call(uintptr(unsafe.Pointer(&blob)))
	if blob == nil || blob.size == 0 {
		return nil, fmt.Errorf("WFP не назвал идентификатор %s", path)
	}
	return append([]byte(nil), unsafe.Slice(blob.data, blob.size)...), nil
}

// packageSID — SID контейнера приложения Store по семейству его пакета: с ним
// процессы приложения выходят в сеть, и он не меняется при обновлениях.
func packageSID(family string) ([]byte, error) {
	p, err := windows.UTF16PtrFromString(family)
	if err != nil {
		return nil, err
	}
	var sid *windows.SID
	r, _, _ := procDeriveAppContainerSid.Call(uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&sid)))
	if err := result(r); err != nil {
		return nil, fmt.Errorf("SID пакета %s: %w", family, err)
	}
	defer windows.FreeSid(sid)
	return append([]byte(nil), unsafe.Slice((*byte)(unsafe.Pointer(sid)), windows.GetLengthSid(sid))...), nil
}

func display(name, description string) fwpmDisplayData0 {
	n, _ := windows.UTF16PtrFromString(name)
	d, _ := windows.UTF16PtrFromString(description)
	return fwpmDisplayData0{name: n, description: d}
}
