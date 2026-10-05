"""Authoring source. Keep this directory out of any contestant workspace."""

import json
import struct
from pathlib import Path
from hard.build_hard import license_case, vm_case, pattern_case
from hard.build_pipeline import pipeline_case
from hard.build_tls import tls_case
from hard.build_delay import build_delay
from hard.build_unwind import build_unwind
from hard.build_stream import build_stream
from hard.build_stream2 import build_stream2
from hard.build_dump import build_dump
from hard.build_repair import build_repair, vectors as repair_vectors, accepted as repair_accepted

ROOT = Path(__file__).resolve().parents[1]
PUBLIC = ROOT / "public"
CASES = []
KEY = {}


def add(cid, title, category, difficulty, scenario, evidence, questions, answers, track="foundations"):
    rels = []
    for name, content in evidence.items():
        rel = f"artifacts/{cid}/{name}"
        target = PUBLIC / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content.strip() + "\n", encoding="utf-8")
        rels.append(rel)
    CASES.append(dict(id=cid, title=title, category=category, difficulty=difficulty, track=track,
                      scenario=scenario, artifacts=rels, questions=questions))
    KEY[cid] = answers


def q(qid, kind, prompt, options=None, points=1):
    item = dict(id=qid, type=kind, prompt=prompt, points=points)
    if options:
        item["options"] = options
    return item


def a(answer, why):
    return dict(answer=answer, resolution=why)


def pe64_fixture():
    """Build a small parseable PE32+ with three sections and one DIR64 relocation."""
    b = bytearray(0xA00)
    b[0:2] = b"MZ"
    struct.pack_into("<I", b, 0x3C, 0x80)
    b[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", b, 0x84, 0x8664, 3, 0, 0, 0, 0xF0, 0x0022)
    o = 0x98
    struct.pack_into("<H", b, o, 0x20B)
    struct.pack_into("<I", b, o + 4, 0x200)
    struct.pack_into("<I", b, o + 8, 0x400)
    struct.pack_into("<I", b, o + 16, 0x1000)
    struct.pack_into("<I", b, o + 20, 0x1000)
    struct.pack_into("<Q", b, o + 24, 0x140000000)
    struct.pack_into("<II", b, o + 32, 0x1000, 0x200)
    struct.pack_into("<HH", b, o + 40, 6, 0)
    struct.pack_into("<HH", b, o + 48, 6, 0)
    struct.pack_into("<I", b, o + 56, 0x4000)
    struct.pack_into("<I", b, o + 60, 0x400)
    struct.pack_into("<H", b, o + 68, 3)
    struct.pack_into("<H", b, o + 70, 0x40)  # IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE
    struct.pack_into("<Q", b, o + 72, 0x100000)
    struct.pack_into("<Q", b, o + 80, 0x1000)
    struct.pack_into("<Q", b, o + 88, 0x100000)
    struct.pack_into("<Q", b, o + 96, 0x1000)
    struct.pack_into("<I", b, o + 108, 16)
    struct.pack_into("<II", b, o + 112 + 5 * 8, 0x3000, 12)
    s = o + 0xF0
    for i, (name, vs, va, rs, rp, flags) in enumerate([
        (b".text", 0x200, 0x1000, 0x200, 0x400, 0x60000020),
        (b".rdata", 0x300, 0x2000, 0x200, 0x600, 0x40000040),
        (b".reloc", 0x200, 0x3000, 0x200, 0x800, 0x42000040),
    ]):
        struct.pack_into("<8sIIIIIIHHI", b, s + i * 40, name, vs, va, rs, rp, 0, 0, 0, 0, flags)
    b[0x400] = 0xC3  # ret
    struct.pack_into("<Q", b, 0x628, 0x140001234)
    b[0x680:0x68B] = b"CASE-PE64\0\0"
    struct.pack_into("<IIHH", b, 0x800, 0x2000, 12, 0xA028, 0)
    target = PUBLIC / "artifacts" / "pe64" / "sample_pe.bin"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b)


pe64_fixture()
add("pe_rva", "RVA frente a offset de archivo", "PE", "media",
    "Un analista recibe un PE64 mínimo y debe extraer una cadena y distinguir bytes presentes en disco de memoria inicializada por el loader. Examina las cabeceras y secciones del binario.",
    {}, [
        q("q1", "hex", "¿Cuál es el offset de archivo para RVA 0x2080? Responde en hexadecimal."),
        q("q2", "single", "¿Qué ocurre con RVA 0x2250 al mapear esta imagen?", {"A":"Está dentro del archivo en offset 0x850.", "B":"Cae en la cola virtual de .rdata y no tiene bytes propios en el archivo.", "C":"Es un RVA de .reloc.", "D":"Está fuera de SizeOfImage."}),
        q("q3", "single", "¿Cuál es el punto de entrada expresado como VA preferida?", {"A":"0x140000400", "B":"0x140001000", "C":"0x140002000", "D":"0x1000"}),
    ], {"q1":a("0x680","RVA 0x2080 pertenece a .rdata: raw 0x600 + 0x80."),
        "q2":a("B",".rdata tiene tamaño virtual 0x300 y raw 0x200; 0x2250 cae en la parte no respaldada por archivo."),
        "q3":a("B","ImageBase 0x140000000 + AddressOfEntryPoint 0x1000.")})
CASES[-1]["artifacts"].append("artifacts/pe64/sample_pe.bin")

add("pe_reloc", "Relocación DIR64 bajo ASLR", "PE", "difícil",
    "La misma imagen se carga en 0x180000000. Reconstruye el parche que aplica el loader en la dirección cubierta por la tabla de relocaciones.",
    {}, [
        q("q1", "hex", "¿Qué valor QWORD queda en RVA 0x2028 tras aplicar la relocación?"),
        q("q2", "single", "¿Qué significa la entrada de relocación 0xA028?", {"A":"HIGHLOW en RVA 0xA028", "B":"DIR64 en RVA 0x2028", "C":"DIR64 en offset de archivo 0x28", "D":"ABSOLUTE en RVA 0x2028"}),
        q("q3", "hex", "¿Cuál es el delta de carga aplicado?"),
    ], {"q1":a("0x180001234","QWORD original 0x140001234 + delta 0x40000000."),
        "q2":a("B","El nibble alto A es IMAGE_REL_BASED_DIR64; offset 0x028 en página RVA 0x2000."),
        "q3":a("0x40000000","0x180000000 - 0x140000000.")})
CASES[-1]["artifacts"].append("artifacts/pe64/sample_pe.bin")

add("abi_x64", "Argumentos y shadow space", "ABI x64", "difícil",
    "Has pausado una función Windows x64 justo al entrar, antes de su prólogo. Identifica los argumentos de una llamada mixta sin confundir shadow space y pila del llamador.",
    {"registers.txt": """
RIP = 00007ff6`21301000  RSP = 000000d2`00b0ff58
RCX = 00000000`00000011  RDX = 00000000`00000022
R8  = 00000000`00000033  R9  = 00000000`00000044
XMM0 = 0.0  XMM1 = 0.0  XMM2 = 0.0  XMM3 = 0.0

dq rsp L8
000000d2`00b0ff58  00007ff6`21302234  11111111`11111111
000000d2`00b0ff68  22222222`22222222  33333333`33333333
000000d2`00b0ff78  44444444`44444444  00000000`00000055
000000d2`00b0ff88  00000000`00000066  00000000`00000000

Firma conocida: uint64_t f(uint64_t a, uint64_t b, uint64_t c,
                             uint64_t d, uint64_t e, uint64_t f);
"""}, [
        q("q1", "hex", "¿Cuál es el quinto argumento, e?"),
        q("q2", "single", "¿Qué representa [rsp+0x20] en este instante?", {"A":"Quinto argumento", "B":"Cuarto slot de shadow space", "C":"Dirección de retorno", "D":"Sexto argumento"}),
        q("q3", "multi", "Selecciona las afirmaciones seguras.", {"A":"RCX contiene a.", "B":"[rsp+0x28] contiene e.", "C":"[rsp+0x30] contiene f.", "D":"[rsp+0x08] está garantizado que contiene a."}),
    ], {"q1":a("0x55","En entrada de callee, retorno en [rsp], shadow space [rsp+8..+27], quinto argumento en [rsp+28]."),
        "q2":a("B","[rsp+20] es el cuarto QWORD del espacio reservado, no un argumento de pila."),
        "q3":a(["A","B","C"],"Los registros transportan los cuatro primeros enteros y los siguientes están tras el shadow space; los home slots no tienen por qué estar rellenados.")})

add("crash_av", "Access violation de lectura", "WinDbg", "media",
    "Una DLL falla tras recibir un contexto opcional. Distingue el tipo de acceso y el dato que falta antes de proponer una reparación.",
    {"dump.txt": """
EXCEPTION_RECORD:  (.exr -1)
ExceptionAddress: 00007ff6`51001a42 (sample!ParseNode+0x32)
ExceptionCode: c0000005 (Access violation)
NumberParameters: 2
Parameter[0]: 0000000000000000
Parameter[1]: 0000000000000018

CONTEXT:  (.ecxr)
rax=0000000000000000 rcx=000001df3b202100
rip=00007ff651001a42 rsp=000000d200b0f870
sample!ParseNode+0x32:
00007ff6`51001a42 488b4818 mov rcx,qword ptr [rax+18h]
00007ff6`51001a46 4885c9   test rcx,rcx

Pseudo source reconstruido: ctx = get_optional_context(node);
                          use(ctx->next);
"""}, [
        q("q1", "single", "¿Qué operación produjo la excepción?", {"A":"Lectura de 0x18", "B":"Escritura en 0x18", "C":"Ejecución en 0x18", "D":"Lectura de 0x0"}),
        q("q2", "single", "¿Qué valor debe comprobarse primero al investigar la causa?", {"A":"RCX tras la instrucción", "B":"RAX y el retorno de get_optional_context", "C":"El byte en RIP+4", "D":"El tamaño de la shadow space"}),
        q("q3", "single", "¿Qué corrección preserva mejor la semántica descrita?", {"A":"Sustituir la instrucción por NOP siempre", "B":"Comprobar ctx antes de acceder a ctx->next y definir la ruta sin contexto", "C":"Cambiar la base preferida de la imagen", "D":"Ignorar todas las excepciones c0000005"}),
    ], {"q1":a("A","Parameter[0]=0 indica lectura; Parameter[1]=0x18 indica la dirección."),
        "q2":a("B","RAX=0 y la instrucción desreferencia [RAX+0x18]."),
        "q3":a("B","La función devuelve un contexto opcional; hay que manejar el caso nulo en el flujo, no ocultar la instrucción.")})

add("wow64_view", "DLL aparentemente ausente", "WOW64", "media",
    "Una herramienta x86 falla al comprobar un DLL nativo y una clave de configuración en Windows x64. El informe de soporte compara resultados de procesos de distinta arquitectura.",
    {"support.txt": r"""
Proceso de diagnóstico: x86 bajo WOW64; Windows: x64.
CreateFileW(L"C:\Windows\System32\nativeprobe.dll") -> ERROR_FILE_NOT_FOUND.
Un proceso x64 abre C:\Windows\System32\nativeprobe.dll con éxito.
El proceso x86 también enumera HKLM\Software\Contoso\Agent y no ve Version.
Un proceso x64 lee Version=7 bajo HKLM\Software\Contoso\Agent.
El DLL solo existe en el directorio nativo x64. No hay solicitud UAC.
"""}, [
        q("q1", "single", "¿Qué ruta permite al proceso x86 acceder al directorio System32 nativo?", {"A":r"C:\Windows\SysWOW64", "B":r"C:\Windows\Sysnative", "C":r"C:\Windows\System32\SysWOW64", "D":r"C:\Windows\WinSxS"}),
        q("q2", "single", "¿Qué bandera permite abrir explícitamente la vista de registro x64 desde x86?", {"A":"KEY_WOW64_32KEY", "B":"KEY_READ", "C":"KEY_WOW64_64KEY", "D":"REG_OPTION_VOLATILE"}),
        q("q3", "multi", "¿Qué conclusiones están sustentadas?", {"A":"La redirección de archivos puede explicar el ERROR_FILE_NOT_FOUND.", "B":"Las vistas de registro separadas pueden explicar la diferencia de Version.", "C":"El DLL nativo x64 podrá cargarse dentro del proceso x86 si se usa Sysnative.", "D":"La ausencia observada desde x86 prueba que el DLL no existe en disco."}),
    ], {"q1":a("B","Sysnative es el alias virtual de WOW64 hacia System32 nativo."),
        "q2":a("C","KEY_WOW64_64KEY selecciona la vista de 64 bits."),
        "q3":a(["A","B"],"Las dos redirecciones explican los resultados; abrir un archivo x64 no lo hace cargable en proceso x86.")})

add("unwind_x64", "Pila rota tras un hook", "Unwind", "difícil",
    "Un plugin inserta un trampolín x64 en memoria ejecutable. Funciona en llamadas normales, pero un volcado tomado dentro del trampolín pierde frames al caminar la pila.",
    {"hook.txt": """
Rango del trampolín: 000001e7`10000000 .. 000001e7`10000030 (MEM_PRIVATE, RX)
Prólogo en +0: push rbx; sub rsp, 30h
En +0x18: call plugin!LogEvent
Epílogo: add rsp,30h; pop rbx; ret

RtlLookupFunctionEntry(000001e7`10000018) -> NULL
La región no aparece en la tabla de funciones de ninguna imagen PE.
El stack walker trata el PC como función leaf y lee [rsp] como retorno.
"""}, [
        q("q1", "single", "¿Por qué falla el unwind en +0x18?", {"A":"Una leaf function necesita siempre .pdata.", "B":"No hay metadatos de unwind para deshacer push rbx y sub rsp,30h.", "C":"RBX es volátil en Windows x64.", "D":"Todo MEM_PRIVATE es ilegible para un depurador."}),
        q("q2", "single", "¿Qué API corresponde a registrar dinámicamente una tabla de funciones para ese código?", {"A":"RtlAddFunctionTable", "B":"VirtualProtect", "C":"SetUnhandledExceptionFilter", "D":"SymInitialize"}),
        q("q3", "multi", "¿Qué campos debe describir el unwind de ese prólogo?", {"A":"El guardado de RBX", "B":"La asignación de 0x30 bytes de pila", "C":"Cada instrucción NOP del cuerpo", "D":"El GUID del PDB"}),
    ], {"q1":a("B","El walker presupone leaf al no hallar RUNTIME_FUNCTION, pero RSP y RBX fueron modificados."),
        "q2":a("A","RtlAddFunctionTable registra entradas RUNTIME_FUNCTION para código generado dinámicamente."),
        "q3":a(["A","B"],"UNWIND_INFO describe los efectos del prólogo sobre pila y registros no volátiles.")})

add("symbols_pdb", "Nombre de función falso por PDB ajeno", "Símbolos", "media",
    "Dos builds de una DLL comparten nombre de archivo y una función se desplazó. Un informe usa símbolos de una build anterior y atribuye el fallo a una función que no está en el binario cargado.",
    {"symbols.txt": """
Módulo cargado: appcore.dll, base 00007ffb`40000000, tamaño 0x40000
CodeView RSDS del módulo: GUID {5AAE44F6-831D-4B2E-BE20-97B6EB7720D2}, Age 3
PDB encontrado en caché: appcore.pdb, GUID {5AAE44F6-831D-4B2E-BE20-97B6EB7720D2}, Age 2
RIP del crash: 00007ffb`400071A0
!lmi appcore: symbols deferred / mismatched
Desensamblado del binario cargado en RVA 0x71A0: mov rax,qword ptr [rcx+20h]
"""}, [
        q("q1", "hex", "¿Cuál es el RVA del RIP?"),
        q("q2", "single", "¿Puede considerarse coincidente ese PDB solo porque coincide el GUID?", {"A":"Sí, Age no forma parte de la identidad.", "B":"No; GUID y Age deben coincidir.", "C":"Sí, si el nombre appcore.pdb coincide.", "D":"No; los PDB nunca sirven con ASLR."}),
        q("q3", "single", "¿Qué dato debe guiar la atribución hasta obtener símbolos correctos?", {"A":"El nombre de función del PDB Age 2", "B":"El RVA y desensamblado del binario cargado", "C":"Solo el timestamp del crash", "D":"La ruta de la caché de PDB"}),
    ], {"q1":a("0x71A0","RIP menos base = 0x71A0."),
        "q2":a("B","CodeView RSDS identifica PDB por GUID y Age; aquí Age difiere."),
        "q3":a("B","El código y la dirección del módulo cargado son evidencia directa; el nombre de un PDB ajeno no lo es.")})

add("loader_lock", "Bloqueo durante DllMain", "Loader", "difícil",
    "Un DLL de telemetría deja colgada la aplicación durante LoadLibraryW. Hay dos hilos vivos y ninguno consume CPU.",
    {"threads.txt": """
Thread 12:
  ntdll!LdrLoadDll
  sample!DllMain(DLL_PROCESS_ATTACH)
  sample!StartWorker
  kernelbase!WaitForSingleObject(worker_ready, INFINITE)

Thread 18 (worker creado por Thread 12):
  ntdll!LdrpCallInitRoutine
  [pendiente de notificación DLL_THREAD_ATTACH]
  sample!WorkerMain -> SetEvent(worker_ready)  [todavía no ejecutado]

El callback DllMain no ha retornado. El worker se creó correctamente.
"""}, [
        q("q1", "single", "¿Cuál es la dependencia circular?", {"A":"WaitForSingleObject necesita un handle x86.", "B":"DllMain espera al worker, cuyo arranque requiere que terminen las notificaciones serializadas del loader.", "C":"CreateThread falla siempre desde DllMain.", "D":"El evento worker_ready se resetea automáticamente antes de esperar."}),
        q("q2", "single", "¿Qué cambio evita esta espera en el loader?", {"A":"Esperar menos tiempo dentro de DllMain.", "B":"Mover inicio y sincronización del worker a una función Init explícita llamada tras LoadLibrary.", "C":"Llamar LoadLibrary otra vez desde DllMain.", "D":"Marcar worker_ready antes de crearlo y seguir asumiendo que inicializó."}),
        q("q3", "single", "¿Qué observación descarta que CreateThread haya fallado?", {"A":"Thread 18 existe y espera el paso de inicialización del loader.", "B":"Thread 12 está en LdrLoadDll.", "C":"El evento es auto reset.", "D":"La DLL tiene exports."}),
    ], {"q1":a("B","El loader serializa las notificaciones; DllMain aún retiene la secuencia que el worker necesita cruzar."),
        "q2":a("B","La inicialización bloqueante debe realizarse fuera de DllMain."),
        "q3":a("A","La traza muestra que el hilo fue creado.")})

add("etw_pid", "PID reciclado en telemetría", "ETW", "difícil",
    "Un detector correlaciona una operación de archivo con un proceso usando solo PID. Un reinicio rápido hace que se atribuya la operación al proceso incorrecto.",
    {"events.csv": """
time_utc,event,pid,process_start_key,image,path
12:00:01.000,ProcessStart,4380,A17,worker.exe,
12:00:03.100,FileWrite,4380,A17,worker.exe,C:\\Temp\\old.bin
12:00:04.000,ProcessStop,4380,A17,worker.exe,
12:00:04.230,ProcessStart,4380,B92,updater.exe,
12:00:04.310,FileWrite,4380,B92,updater.exe,C:\\Temp\\new.bin
12:00:05.000,ProcessStop,4380,B92,updater.exe,
"""}, [
        q("q1", "single", "¿A qué instancia pertenece new.bin?", {"A":"worker.exe/A17", "B":"updater.exe/B92", "C":"A ambas", "D":"No se puede distinguir con los datos"}),
        q("q2", "single", "¿Qué clave de correlación evita la confusión mostrada?", {"A":"PID solamente", "B":"Nombre de imagen solamente", "C":"PID más process_start_key", "D":"Ruta de archivo solamente"}),
        q("q3", "single", "¿Cuál es el fallo del algoritmo que usa PID como identidad permanente?", {"A":"La hora UTC está redondeada", "B":"Los PID se pueden reutilizar tras terminar un proceso", "C":"ETW convierte rutas a UTF-8", "D":"Los eventos FileWrite siempre carecen de PID"}),
    ], {"q1":a("B","El evento lleva clave B92 y ocurre después del nuevo ProcessStart."),
        "q2":a("C","La clave de inicio distingue instancias que comparten PID en momentos diferentes."),
        "q3":a("B","El mismo PID 4380 identifica dos procesos consecutivos.")})

add("plugin_lifetime", "Puntero tras descargar un DLL", "Lifecycle", "media",
    "La aplicación almacena un callback exportado por un plugin y lo llama tras una recarga. El fallo solo aparece en algunas ejecuciones.",
    {"timeline.txt": """
t0 LoadLibraryW(plugin.dll) -> HMODULE 00007ff9`a1000000
t1 GetProcAddress(h, "Process") -> 00007ff9`a1001430
t2 registry.callback = 00007ff9`a1001430
t3 FreeLibrary(h) -> TRUE; reference count reaches 0; image unmapped
t4 another.dll loads; address range may be reused
t5 registry.callback() -> AV or unexpected code
"""}, [
        q("q1", "single", "¿Qué causa explica el comportamiento intermitente?", {"A":"El export cambia de nombre en cada llamada", "B":"El callback queda apuntando a memoria de un módulo descargado", "C":"GetProcAddress devuelve siempre una dirección relativa", "D":"FreeLibrary invalida todos los hilos del proceso"}),
        q("q2", "single", "¿Qué reparación conserva la validez del callback?", {"A":"Retener una referencia al módulo mientras cualquier callback pueda ejecutarse y retirarlo antes de descargar", "B":"Guardar solo los 32 bits bajos del puntero", "C":"Volver a llamar el puntero hasta que funcione", "D":"Desactivar ASLR"}),
        q("q3", "single", "¿Por qué a veces se ejecuta código inesperado en vez de una AV?", {"A":"La dirección antigua puede quedar asignada a otro módulo", "B":"El export es forwarder", "C":"El retorno de GetProcAddress es ASCII", "D":"El loader reescribe el registro"}),
    ], {"q1":a("B","FreeLibrary libera la última referencia y desmapea la imagen; el puntero persistente queda colgando."),
        "q2":a("A","Debe existir una garantía de vida útil del módulo hasta que terminen todos los usos del callback."),
        "q3":a("A","La reutilización del rango puede convertir el puntero colgante en una dirección ejecutable de otro código.")})

add("x86_stack", "Inferencia de convención x86", "ABI x86", "difícil",
    "Una función x86 sin símbolos se invoca desde dos sitios. Hay que inferir quién limpia la pila, sin atribuir más semántica de la que permite el desensamblado.",
    {"disasm.txt": """
Caller:
  push 4
  push esi
  push 0
  push edi
  call 00402700
  mov  ebx,eax
  ; no add esp,10h here

00402700:
  push ebp
  mov  ebp,esp
  mov  eax,[ebp+08h]
  ; ...
  mov  esp,ebp
  pop  ebp
  ret  10h
"""}, [
        q("q1", "hex", "¿Cuántos bytes de argumentos retira el callee además de la dirección de retorno?"),
        q("q2", "single", "¿Qué afirmación está mejor sustentada?", {"A":"El llamador limpia cuatro argumentos", "B":"El callee limpia 16 bytes de argumentos", "C":"Es necesariamente __thiscall de MSVC", "D":"El retorno es de tipo void"}),
        q("q3", "single", "¿Por qué sería excesivo afirmar una convención de fuente exacta solo con estas instrucciones?", {"A":"ret 10h no existe en x86", "B":"Código ensamblador o convenciones personalizadas pueden compartir el mismo patrón de limpieza", "C":"Los argumentos nunca se pasan por pila", "D":"EAX no puede contener resultados"}),
    ], {"q1":a("0x10","ret 10h retira 0x10 bytes de argumentos después de consumir la dirección de retorno."),
        "q2":a("B","El ret inmediato prueba limpieza de cuatro DWORD por el callee."),
        "q3":a("B","La secuencia no identifica por sí sola el atributo de lenguaje fuente.")})

add("rip_relative", "Destino de acceso RIP relative", "x64 assembly", "media",
    "En dos builds de un programa x64, una instrucción accede a un global con desplazamiento relativo. Calcula el destino efectivo y distingue el desplazamiento embebido de una dirección absoluta.",
    {"disasm.txt": """
Build 1, image base 00000001`80000000:
00000001`80005120  48 8B 05 D9 F9 FF FF  mov rax,qword ptr [rip-627h]
00000001`80005127  48 85 C0              test rax,rax

Build 2, image base 00000001`90000000:
00000001`90006310  48 8B 05 E9 07 00 00  mov rax,qword ptr [rip+7E9h]
00000001`90006317  48 85 C0              test rax,rax
"""}, [
        q("q1", "hex", "¿Qué VA lee la instrucción de Build 1?"),
        q("q2", "hex", "¿Qué RVA lee la instrucción de Build 2?"),
        q("q3", "single", "Para una firma que sobreviva a ambos builds, ¿qué parte debe tratarse como variable?", {"A":"El opcode 48 8B 05", "B":"Los cuatro bytes disp32 tras 48 8B 05", "C":"Los bytes 48 85 C0", "D":"El prefijo REX siempre debe omitirse"}),
    ], {"q1":a("0x180004B00","RIP apunta a la siguiente instrucción 0x180005127; -0x627 = 0x180004B00."),
        "q2":a("0x6B00","0x6317 + 0x7E9 = 0x6B00."),
        "q3":a("B","El disp32 cambia aunque la forma de la instrucción se conserva.")})

add("xor_config", "Configuración codificada en un recurso", "Data RE", "difícil",
    "Un programa interno guarda un bloque de configuración de prueba en un recurso. El encabezado indica longitud y XOR de un byte; la muestra no se ejecuta. Recupera el contenido a partir del archivo binario.",
    {"format.txt": """
Formato del recurso config.dat:
offset 0..3 : ASCII 'XCFG'
offset 4    : clave XOR (un byte)
offset 5    : longitud de payload (un byte)
offset 6..  : payload con cada byte XOR clave
El payload es texto ASCII terminado exactamente por la longitud; no hay NUL implícito.
"""}, [
        q("q1", "single", "¿Cuál es el texto decodificado?", {"A":"MODE=SAFE;PORT=8443", "B":"MODE=FAST;PORT=443", "C":"MODE=SAFE;PORT=443", "D":"MODE=TEST;PORT=8443"}),
        q("q2", "hex", "¿Cuál es la clave XOR?"),
        q("q3", "single", "¿Por qué no debe tratarse el payload codificado como string C sin decodificar?", {"A":"El formato define una longitud explícita y no garantiza NUL", "B":"Los recursos PE siempre usan UTF-16", "C":"XOR cambia el tamaño de cada byte", "D":"ASCII no admite signos igual"}),
    ], {"q1":a("A","XOR con 0x5A de los bytes tras la cabecera da MODE=SAFE;PORT=8443."),
        "q2":a("0x5A","La clave está en offset 4."),
        "q3":a("A","La longitud en offset 5 delimita el payload.")})
payload = b"MODE=SAFE;PORT=8443"
resource = b"XCFG" + bytes([0x5A, len(payload)]) + bytes(x ^ 0x5A for x in payload)
resource_path = PUBLIC / "artifacts" / "xor_config" / "config.dat"
resource_path.write_bytes(resource)
CASES[-1]["artifacts"].append("artifacts/xor_config/config.dat")

add("com_activation", "Dos fallos distintos al activar COM", "COM", "difícil",
    "Una aplicación x86 intenta activar un componente de informes y el equipo mezcla dos errores en una sola hipótesis. Separa el cambio de apartamento de la incompatibilidad de arquitectura.",
    {"com_trace.txt": """
Proceso: reporthost.exe (x86), Windows x64
Hilo UI: CoInitializeEx(NULL, COINIT_APARTMENTTHREADED) -> S_OK
Hilo UI: CoInitializeEx(NULL, COINIT_MULTITHREADED) -> 0x80010106

Registro comprobado en vista x64:
HKCR\\CLSID\\{02C92310-8408-4B39-9C1B-11C822982501}\\InprocServer32
  (Default) = C:\\Program Files\\Contoso\\ReportCom64.dll (PE32+, AMD64)

El cliente solicita CLSCTX_INPROC_SERVER. No existe build x86 del DLL.
El equipo propone copiar ReportCom64.dll a SysWOW64 y reintentar.
"""}, [
        q("q1", "single", "¿Qué significa 0x80010106 en este hilo?", {"A":"Falta un DLL en System32", "B":"Se intentó cambiar el modelo de apartamento ya fijado", "C":"El servidor COM se registró dos veces", "D":"El objeto agotó memoria"}),
        q("q2", "single", "¿Resolverá copiar el DLL x64 a SysWOW64 la activación in-process desde x86?", {"A":"Sí, SysWOW64 convierte arquitectura", "B":"Sí, si se cambia la extensión a .ocx", "C":"No, un proceso x86 no puede cargar un DLL x64", "D":"No, porque COM no admite servidores in-process"}),
        q("q3", "multi", "Selecciona reparaciones técnicamente válidas para los problemas independientes.", {"A":"Inicializar el hilo con un único modelo COM coherente", "B":"Proporcionar un servidor in-process x86 compatible", "C":"Usar un servidor COM out-of-process x64 con marshaling adecuado", "D":"Copiar el DLL x64 a SysWOW64"}),
    ], {"q1":a("B","RPC_E_CHANGED_MODE indica un segundo CoInitializeEx incompatible con el STA ya establecido."),
        "q2":a("C","La ruta del archivo no altera la arquitectura del código."),
        "q3":a(["A","B","C"],"Hay que corregir el apartamento del hilo y elegir arquitectura compatible o frontera entre procesos.")})

add("aob_versions", "Firma que falla tras actualizar", "Patrones", "difícil",
    "Una firma AOB se construyó con bytes de una instrucción RIP-relative. En la siguiente versión cambia el layout; además aparece un segundo bloque con el mismo prefijo. Diseña una firma estable y justifica cómo discriminar el match.",
    {"versions.txt": """
Build A, bloque objetivo en RVA 0x4210:
48 8B 05 72 13 00 00 48 85 C0 74 09 8B 48 08 85 C9

Build B, bloque objetivo en RVA 0x5A70:
48 8B 05 E2 F0 FF FF 48 85 C0 74 0C 8B 48 08 85 C9

Build B, bloque NO objetivo en RVA 0x7C10:
48 8B 05 31 02 00 00 48 85 C0 74 0C 8B 50 08 85 D2

Los cuatro bytes después de 48 8B 05 son disp32; el byte después de 74 es un salto corto.
"""}, [
        q("q1", "single", "¿Qué patrón conserva bytes estables y distingue el bloque objetivo de ambos builds?", {"A":"48 8B 05 ?? ?? ?? ?? 48 85 C0 74 ?? 8B 48 08 85 C9", "B":"48 8B 05 72 13 00 00 48 85 C0 74 09", "C":"48 8B 05 ?? ?? ?? ?? 48 85 C0", "D":"?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??"}),
        q("q2", "multi", "¿Qué partes cambian explícitamente entre las dos versiones objetivo?", {"A":"El disp32 de mov", "B":"El desplazamiento del jz corto", "C":"La secuencia 8B 48 08 85 C9", "D":"El opcode 48 85 C0"}),
        q("q3", "single", "¿Qué comprobación adicional es prudente antes de usar el resultado de un sigscan en otra actualización?", {"A":"Aceptar siempre el primer match", "B":"Verificar unicidad, límites de instrucción y semántica del destino RIP-relative", "C":"Eliminar todos los wildcards", "D":"Interpretar el disp32 como VA absoluta"}),
    ], {"q1":a("A","Enmascara desplazamientos variables y conserva el sufijo que diferencia el no objetivo."),
        "q2":a(["A","B"],"Cambian los cuatro bytes de RIP-relative y el salto corto; el resto objetivo permanece."),
        "q3":a("B","Una firma necesita validación del match y de la referencia calculada, no solo una coincidencia de bytes.")})

license_info = license_case()
add("hard_license", "Licencia cifrada con ruta retirada", "PE práctico", "extremo",
    "Tienes un PE64 de consola sin PDB. La aplicación acepta un código actual de 20 caracteres al llamarla "
    "con un único argumento; existe una ruta histórica `--retired` que no sirve para la activación normal. "
    "Recupera ambos códigos y los valores internos pedidos mediante análisis del binario. No hay código fuente público.",
    {"brief.txt": """
Muestra obtenida de una build Windows x64. Comportamiento observable:
  license_probe.exe <candidato>             -> ACCEPT o REJECT
  license_probe.exe --retired <candidato>   -> RETIRED ACCEPT o REJECT

El código actual tiene 20 caracteres ASCII. No se conoce ningún candidato válido.
El ejecutable contiene CRT estático y dos recorridos de verificación.
SHA256 y tamaño del PE pueden verificarse localmente; la fuente/PDB no se entrega.
"""}, [
        q("q1", "literal", "¿Cuál es el código ACTUAL exacto de 20 caracteres? Respeta mayúsculas.", points=20),
        q("q2", "literal", "¿Cuál es el código RETIRADO exacto aceptado solo con --retired?", points=5),
        q("q3", "hex", "¿Cuál es el estado uint32 del generador actual tras producir las primeras 10 máscaras (índices 0..9)?", points=6),
        q("q4", "hex", "¿Cuál es el RVA de inicio de la rutina que descifra el código actual?", points=5),
    ], {"q1":a(license_info["real"],"El programa descifra current_cipher con el generador y compara los 20 bytes del candidato."),
        "q2":a(license_info["retired"],"La ruta --retired usa un seed y array distintos; no participa en la activación normal."),
        "q3":a(hex(license_info["state_after_10"]),"Aplicar diez iteraciones de la recurrencia de 32 bits con wraparound."),
        "q4":a(hex(license_info["decode_rva"]),"Seguir la llamada desde check_candidate a la rama que usa current_cipher.")}, track="expert")
CASES[-1]["artifacts"].append("artifacts/hard_license/license_probe.exe")

vm_info = vm_case()
add("hard_vm", "Bytecode cifrado y validación permutada", "VM práctico", "extremo",
    "Un segundo PE64 valida un código de 16 caracteres mediante bytecode propio guardado en una sección PE adicional. "
    "El binario solo informa ACCEPT o REJECT; identifica la transformación de la sección, interpreta el programa "
    "y reconstruye el código. El orden de lectura de caracteres no coincide con su posición en el texto.",
    {"brief.txt": """
Uso: vm_guard.exe <candidato-de-16-caracteres>
Salida: ACCEPT o REJECT.

Notas de triage: el PE tiene una sección no estándar que contiene aproximadamente 243 bytes
de datos. El punto de entrada del runtime llega a dos rutinas propias: una copia y transforma
esos bytes; la otra ejecuta instrucciones de longitud fija. No se dispone de PDB.
"""}, [
        q("q1", "literal", "¿Cuál es el código exacto de 16 caracteres aceptado por el VM?", points=25),
        q("q2", "hex", "¿Qué valor inicial de 8 bits usa la máscara con que se descifra el bytecode?", points=4),
        q("q3", "single", "¿Qué hace el opcode 0x5B al registro de 8 bits?", {"A":"Rotación izquierda por arg bits", "B":"Rotación derecha por arg bits", "C":"XOR con arg", "D":"Lectura de input[arg]"}, points=4),
        q("q4", "literal", "¿En qué orden se validan los primeros cuatro índices de input? Responde exactamente `i,j,k,l` sin espacios.", points=6),
        q("q5", "literal", "SHA-256 hexadecimal (minúsculas) de los 243 bytes de bytecode DESCIFRADO.", points=8),
    ], {"q1":a(vm_info["secret"],"Invertir LOAD/XOR/ROL/ADD/CMP para cada índice en el orden del programa."),
        "q2":a(hex(vm_info["mask_seed"]),"Seed de la recurrencia byte = byte*73+41 antes de cada XOR."),
        "q3":a("A","El intérprete rota el acumulador de 8 bits a la izquierda."),
        "q4":a(",".join(map(str,vm_info["permutation"][:4])),"Las primeras cuatro instrucciones LOAD apuntan a esos índices."),
        "q5":a(vm_info["program_sha256"],"Hash del programa tras deshacer el stream XOR, antes de interpretarlo.")}, track="expert")
CASES[-1]["artifacts"].append("artifacts/hard_vm/vm_guard.exe")

pattern_info = pattern_case()
add("hard_pattern", "Firma robusta entre tres builds PE64", "Patrones PE", "extremo",
    "Dispones de tres versiones de la misma utilidad PE64 sin símbolos. El objetivo es la rutina viva que lee "
    "el campo de modo en desplazamiento 0x2A8 de una estructura; hay otra rutina de auditoría que lee "
    "el mismo campo. Encuentra la rutina viva en cada build, construye una firma AOB que la identifique "
    "una sola vez en `.text` de las tres y calcula un resultado de la versión más nueva.",
    {"brief.txt": """
layout_v1.exe, layout_v2.exe y layout_v3.exe son builds x64 del mismo programa.
La función principal combina el resultado de la rutina viva con auditoría y helpers
antes de imprimir. Por ello, ejecutar el EXE no entrega directamente el valor de
la rutina viva. El campo de modo es un DWORD en +0x2A8 desde el contexto.
Los tres PE tienen ImageBase preferida 0x140000000 y no incluyen PDB.
"""}, [
        q("q1", "hex", "RVA inicial de la rutina viva en layout_v1.exe.", points=5),
        q("q2", "hex", "RVA inicial de la rutina viva en layout_v2.exe.", points=5),
        q("q3", "hex", "RVA inicial de la rutina viva en layout_v3.exe.", points=5),
        q("q4", "single", "¿Qué patrón AOB encuentra exactamente una vez la rutina viva en los tres `.text`?", {
            "A":"8B 81 A8 02 00 00 35 ?? ?? ?? ?? ?? ?? ?? ?? ?? C1 C8 1D C3",
            "B":"8B 81 A8 02 00 00",
            "C":"8B 81 A8 02 00 00 35 19 7E 5C A3 05 03 2A 4F 17 C1 C8 1D C3",
            "D":"8B 81 A8 02 00 00 35 ?? ?? ?? ?? 05 ?? ?? ?? ?? C1 C8 1D C3",
        }, points=8),
        q("q5", "hex", "Resultado de la rutina viva de layout_v3 para modo de entrada 0x12345678 (sin XOR con auditoría ni helpers).", points=6),
    ], {"q1":a(hex(pattern_info["versions"][0]["target_rva"]),"Identificar el lector seguido de XOR, aritmética y rotación; el otro lector es auditoría."),
        "q2":a(hex(pattern_info["versions"][1]["target_rva"]),"El desplazamiento de código cambió tras compilar la segunda versión."),
        "q3":a(hex(pattern_info["versions"][2]["target_rva"]),"La tercera versión añade más instrucciones antes de la rutina objetivo."),
        "q4":a("A","Se enmascaran inmediatos variables y el opcode add/sub; el sufijo ROR3 y la carga +0x2A8 fijan la semántica. Validado único en las tres .text."),
        "q5":a(hex(pattern_info["v3_target_result"]),"En v3: XOR 0x76E2845D, suma modular 0xE13B6709 (compilada como SUB negativo), rotación izquierda 3.")}, track="expert")
CASES[-1]["artifacts"].extend(f"artifacts/hard_pattern/layout_v{version}.exe" for version in (1,2,3))

tls_info = tls_case()
add("hard_tls_state", "Estado cifrado inicializado por TLS antes de main", "TLS PE y RE funcional", "extremo++",
    "Este PE64 sin PDB calcula una transformación de dos enteros uint64. El contenido inicial de ciertas "
    "variables globales en disco no coincide con el estado que usa la función viva. Reconstruye el proceso "
    "de inicialización y la transformación completa. El programa de q1 se probará con 256 pares ocultos "
    "que recorren todas las ramas del bucle. No se entrega código fuente.",
    {"brief.txt": """
Uso: tls_oracle.exe 0xX 0xY
Salida: 16 dígitos hexadecimales; código de salida 2 si los argumentos son inválidos.

El PE64 incluye CRT estático y relocaciones. El oráculo puede ejecutarse con
cuantas entradas de prueba necesites. El corrector compara el programa DSL de q1
con el ejecutable en 256 pares ocultos, incluidos valores frontera. Se concede
crédito parcial según la proporción de resultados correctos.
""",
     "dsl_tls.txt": """
Formato de answers.q1: objeto JSON con `steps` (1..64 pasos de nivel superior),
`return` y, opcionalmente, `tables`. Registro inicial: x, y (uint64).
Destinos: r0..r31. Operando: registro ya definido, i dentro de un bucle,
constante entera JSON o cadena hexadecimal `0x...`. Aritmética módulo 2^64.

Operaciones add, sub, xor, and, or, mul: dst, a, b.
Operaciones rol, ror, shl, shr: dst, a, bits (entero 0..63).
Operación not: dst, a. Operación sel: dst, cond, a, b;
elige a si cond != 0, y b en caso contrario.

`tables` es un objeto de hasta cuatro tablas. Cada tabla contiene 1..16
constantes uint64, por ejemplo `"keys":["0xA1","0xB2"]`.
`lookup`: dst, table, index. Usa `index % longitud(tabla)`.
`loop`: count (1..16), body (1..32 pasos); ejecuta body count veces.
Dentro del cuerpo, i vale 0,1,...,count-1. No se admiten bucles anidados.
El límite total de pasos ejecutados por evaluación es 256.

Ejemplo de sintaxis, NO es la solución:
{"tables":{"k":["0x5","0x7"]},"steps":[
 {"dst":"r0","op":"xor","a":"x","b":"0x1"},
 {"op":"loop","count":2,"body":[
   {"dst":"r1","op":"lookup","table":"k","index":"i"},
   {"dst":"r0","op":"add","a":"r0","b":"r1"}]}
],"return":"r0"}

Devuelve el objeto como answers.q1, sin escapar el JSON como texto.
El corrector interpreta este DSL; no ejecuta código fuente del agente.
"""}, [
        q("q1", "pipeline64", "Recupera la transformación completa como programa DSL para cualquier x,y uint64.", points=100),
        q("q2", "hex", "RVA del callback que inicializa el estado usado por la función viva.", points=8),
        q("q3", "hex", "RVA inicial de la función que transforma x,y después de la inicialización.", points=8),
        q("q4", "hex", "Valor uint64 real de la primera entrada de la tabla de claves tras la inicialización.", points=6),
        q("q5", "hex", "Salida para x=0x0123456789ABCDEF, y=0xFEDCBA9876543210.", points=4),
        q("q6", "single", "¿Qué explica que los QWORD iniciales de la tabla en disco sean señuelos?", {
            "A":"El loader convierte automáticamente cada QWORD de .data de big endian a little endian.",
            "B":"Un callback en el directorio TLS reescribe la tabla antes de main.",
            "C":"La resolución de imports diferidos aplica XOR a toda la sección .data.",
            "D":"El prologo de mix_tls restaura las claves desde la shadow space de su llamador.",
        }, points=4),
    ], {"q1":a(tls_info["program"],"Seguir el callback TLS, descifrar las ocho claves y modelar las ocho iteraciones con lookup y loop; validar contra el oráculo."),
        "q2":a(hex(tls_info["callback_rva"]),"La dirección figura en la lista de callbacks del directorio TLS del PE."),
        "q3":a(hex(tls_info["function_rva"]),"Seguir la llamada desde main después de la comprobación del estado inicializado."),
        "q4":a(hex(tls_info["key0"]),"El callback descifra la primera entrada, que reemplaza el valor señuelo en .data."),
        "q5":a(hex(tls_info["sample"]),"Consultar el oráculo o ejecutar el programa reconstruido con esos parámetros."),
        "q6":a("B","Los callbacks TLS del loader se ejecutan antes de la entrada normal del programa y actualizan la tabla.")},
    track="research")
CASES[-1]["artifacts"].append("artifacts/hard_tls/tls_oracle.exe")

delay_info = build_delay()
add("hard_delay_import", "Reconstrucción de un delay import y su descarga", "PE loader", "extremo++",
    "Analiza un PE64 enlazado con /DELAYLOAD:USER32.dll y /DELAY:UNLOAD. El programa llama dos veces "
    "a la misma API y descarga el módulo entre ambas. Extrae el descriptor de importación retardada "
    "del ejecutable, traduce RVAs a offsets y razona sobre el estado del IAT. No se entrega fuente.",
    {"brief.txt": """
El ejecutable es un PE64 de consola compilado con MSVC, sin PDB.
Su primera llamada a GetForegroundWindow carga USER32.dll si hace falta.
Después invoca __FUnloadDelayLoadedDLL2("USER32.dll") y vuelve a llamar a la API.
Usa el DataDirectory[13] del Optional Header y el descriptor IMAGE_DELAYLOAD_DESCRIPTOR.
Todas las cifras solicitadas son de la imagen en disco, antes de la primera llamada,
salvo donde la pregunta indique expresamente otro estado.
"""}, [
        q("q1", "hex", "RVA del descriptor de delay import de USER32.dll.", points=6),
        q("q2", "hex", "RVA de la Unload IAT (UIAT) que permite restaurar el estado de los thunks.", points=7),
        q("q3", "hex", "Offset de archivo del primer QWORD de esa UIAT; no respondas con un RVA.", points=7),
        q("q4", "hex", "Valor VA de 64 bits del primer thunk del delay IAT en la imagen en disco.", points=7),
        q("q5", "hex", "RVA de la variable donde el helper almacena el HMODULE de USER32.dll.", points=5),
        q("q6", "multi", "Selecciona todas las afirmaciones correctas para ESTE descriptor.", {
            "A":"El bit RvaBased de grAttrs está activado; los campos de dirección del descriptor se interpretan como RVAs.",
            "B":"pIAT apunta a una tabla de QWORDs que guarda el HMODULE, no direcciones de función.",
            "C":"pUnloadIAT conserva una copia de los thunks iniciales para restaurar el delay IAT al descargar.",
            "D":"pBoundIAT y pUnloadIAT son el mismo campo del descriptor.",
            "E":"El RVA de pUnloadIAT debe sumarse a ImageBase para obtener su VA preferida."
        }, points=10),
        q("q7", "single", "Si la descarga tiene éxito y se vuelve a llamar a GetForegroundWindow, ¿qué secuencia concuerda con el helper de delay load?", {
            "A":"La UIAT se borra y el IAT queda permanentemente con la dirección antigua de USER32.dll.",
            "B":"El IAT recupera los thunks iniciales desde la UIAT y la nueva llamada vuelve a resolver la DLL.",
            "C":"El loader ejecuta el callback TLS de USER32.dll para restaurar los thunks en el archivo.",
            "D":"El valor de pBoundIAT se ejecuta directamente como una función."
        }, points=6),
    ], {"q1":a(hex(delay_info["descriptor_rva"]),"Localizar el descriptor de USER32.dll a partir del directorio 13."),
        "q2":a(hex(delay_info["unload_rva"]),"Leer pUnloadIAT, el séptimo DWORD del descriptor RVA-based."),
        "q3":a(hex(delay_info["unload_file_offset"]),"Convertir el RVA de la UIAT mediante la sección que lo respalda en disco."),
        "q4":a(hex(delay_info["first_iat"]),"Leer el primer QWORD del delay IAT antes de la resolución dinámica."),
        "q5":a(hex(delay_info["phmod_rva"]),"pHmod señala la celda que recibe el handle del módulo."),
        "q6":a(["A", "C", "E"],"RvaBased=1; pUnloadIAT guarda copia del IAT original y RVA+ImageBase da la VA preferida."),
        "q7":a("B","La descarga restaura el IAT desde la UIAT; la siguiente llamada pasa de nuevo por el helper.")},
    track="research")
CASES[-1]["artifacts"].append("artifacts/hard_delay/delay_probe.exe")

unwind_info = build_unwind()
stack_rsp = 0x000000C00100FE70
caller_rsp = stack_rsp + 0xA0
saved_rbx = 0x1122334455667788
return_rip = 0x00007FF612345678
add("hard_unwind_frame", "Virtual unwind de una rutina MASM x64", "Unwind x64", "extremo++",
    "Un PE64 contiene una rutina con prólogo y epílogo escritos en ensamblador MASM y metadatos reales "
    "en .pdata/.xdata. Reconstruye el marco al detenerla dentro del cuerpo. El volcado de pila es "
    "sintético, pero corresponde exactamente al prólogo del ejecutable. No se entrega fuente.",
    {"context.txt": f"""
Imagen cargada en VA preferida 0x140000000. RIP = 0x{0x140000000 + unwind_info['target_rva'] + 0x10:016X}
La detención ocurre en el cuerpo de la rutina, después de su prólogo y antes del epílogo.
RSP = 0x{stack_rsp:016X}    RBP = 0x{stack_rsp + 0x20:016X}
RBX = 0x0123456789ABCDEF

Memoria QWORD del hilo:
[RSP+0x88] = 0x{saved_rbx:016X}
[RSP+0x90] = 0x000000C00100FFA0
[RSP+0x98] = 0x{return_rip:016X}

Se pide el contexto DEL LLAMADOR después de aplicar VirtualUnwind desde este RIP.
Para las preguntas de metadatos, lee las estructuras reales del PE en disco.
"""}, [
        q("q1", "hex", "RVA de comienzo de la rutina MASM cubierta por el RUNTIME_FUNCTION pertinente.", points=6),
        q("q2", "hex", "RVA del UNWIND_INFO al que apunta ese RUNTIME_FUNCTION.", points=7),
        q("q3", "hex", "Bytes realmente reservados por UWOP_ALLOC_LARGE; interpreta también su slot adicional.", points=7),
        q("q4", "hex", "Offset efectivo en bytes entre RBP y RSP fijado por UWOP_SET_FPREG.", points=7),
        q("q5", "hex", "RSP reconstruido del llamador después de retirar el return address.", points=8),
        q("q6", "hex", "RBX no volátil restaurado en el contexto del llamador.", points=7),
        q("q7", "hex", "RIP de retorno reconstruido del llamador.", points=7),
        q("q8", "single", "Si RIP estuviera justo después de los dos PUSH iniciales y antes de SUB RSP, ¿qué parte del prólogo desharía el unwind en ese punto?", {
            "A":"Los dos PUSH; todavía no la reserva de 0x88 ni el establecimiento de RBP.",
            "B":"La reserva de 0x88 y SET_FPREG; todavía no los PUSH.",
            "C":"Todo el prólogo, porque .pdata no guarda desplazamientos de instrucciones.",
            "D":"Ningún paso: en x64 solo se desenrolla el epílogo."
        }, points=6),
    ], {"q1":a(hex(unwind_info["target_rva"]),"Buscar la entrada de .pdata cuyo BeginAddress cubre el RIP del cuerpo."),
        "q2":a(hex(unwind_info["unwind_rva"]),"La tercera DWORD de RUNTIME_FUNCTION es el RVA del UNWIND_INFO."),
        "q3":a(hex(unwind_info["alloc_size"]),"UWOP_ALLOC_LARGE con OpInfo=0 usa el siguiente slot multiplicado por 8."),
        "q4":a(hex(unwind_info["frame_offset"] * 16),"FrameOffset en el header de UNWIND_INFO se expresa en unidades de 16 bytes."),
        "q5":a(hex(caller_rsp),"RSP actual +0x88 de reserva +0x10 de PUSHs +0x8 de dirección de retorno."),
        "q6":a(hex(saved_rbx),"El PUSH RBX guardó su valor del llamador en [RSP+0x88]."),
        "q7":a(hex(return_rip),"El return address está tras la reserva y los dos registros guardados."),
        "q8":a("A","Los CodeOffset permiten aplicar solo operaciones del prólogo ya ejecutadas.")},
    track="research")
CASES[-1]["artifacts"].append("artifacts/hard_unwind/unwind_probe.exe")

stream_info = build_stream()
add("hard_resource_stream", "Reconstruir una función de longitud variable desde un recurso PE", "Recursos PE y RE funcional", "extremo+++",
    "Este PE64 de consola acepta de 0 a 96 bytes en hexadecimal y devuelve una etiqueta de 64 bits. "
    "El estado real no está en los QWORD iniciales de .data: se deriva de un recurso RCDATA de Windows. "
    "Existe otro recurso de tamaño similar y una rutina de diagnóstico que calcula otro valor. "
    "Reconstruye la función que produce la salida del programa para cualquier entrada permitida. "
    "El corrector ejecutará tu programa declarativo con 384 mensajes ocultos de longitud y contenido variados. "
    "No se entrega código fuente ni PDB.",
    {"brief.txt": """
Uso: stream_oracle.exe HEX
HEX contiene un número par de dígitos hexadecimales, sin prefijo; usa '-' para
el mensaje vacío. Longitud máxima: 96 bytes. La salida correcta tiene 16 dígitos
hexadecimales. Entrada inválida: código de salida 2.

El oráculo puede consultarse. La clave q1 debe representar la transformación
completa, no solo las muestras visibles. El corrector compara la salida del DSL
con el ejecutable en 384 entradas ocultas: longitudes frontera, bytes uniformes,
secuencias y entradas aleatorias. Hay crédito proporcional por coincidencias.
""",
     "dsl_stream.txt": """
Formato de answers.q1: objeto JSON con `steps` (1..64 pasos) y `return`.
Puede incluir `tables` con hasta 4 tablas de 1..16 constantes uint64.
Registro inicial: n = número de bytes del mensaje. Destinos: r0..r31.
Un operando es un registro definido, entero JSON o cadena hexadecimal `0x...`.
Todas las operaciones numéricas son módulo 2^64.

Operaciones add, sub, xor, and, or, mul: dst, a, b.
Operaciones rol, ror, shl, shr: dst, a, bits (entero fijo 0..63).
Operación not: dst, a. sel: dst, cond, a, b (a si cond != 0).
lookup: dst, table, index; índice reducido módulo la longitud de la tabla.

`each`: body (1..32 pasos), itera una vez por byte del mensaje, en orden.
Solo dentro de body existen `byte` (0..255) e `i` (posición desde 0).
El cuerpo puede actualizar registros creados antes del bucle. No se admiten
bucles anidados. Se limita a 4096 el total de pasos ejecutados por entrada.
El bucle de un mensaje vacío no ejecuta ninguna instrucción de body.

Ejemplo de sintaxis, NO es la solución:
{"tables":{"k":["0x5","0x7"]},"steps":[
 {"dst":"r0","op":"xor","a":"n","b":"0x1"},
 {"op":"each","body":[
   {"dst":"r1","op":"lookup","table":"k","index":"i"},
   {"dst":"r0","op":"add","a":"r0","b":"byte"}]}
],"return":"r0"}

Devuelve este objeto como valor de answers.q1; no envíes código Python ni
serialices el JSON como cadena. El corrector interpreta el DSL de forma acotada.
"""}, [
        q("q1", "stream64", "Recupera la función completa de longitud variable como programa DSL.", points=160),
        q("q2", "hex", "RVA inicial de la función que produce el valor impreso (sin incluir el diagnóstico).", points=8),
        q("q3", "hex", "Identificador numérico del recurso RCDATA que aporta el estado real.", points=8),
        q("q4", "hex", "Primer uint64 efectivo de la tabla de claves, después de descifrar el recurso.", points=10),
        q("q5", "hex", "Salida de la función para el mensaje vacío (`-`).", points=6),
        q("q6", "hex", "Salida para el mensaje de 16 bytes 00112233445566778899AABBCCDDEEFF.", points=6),
        q("q7", "multi", "Selecciona todas las afirmaciones que describen el camino que produce la salida.", {
            "A":"Se carga un recurso RCDATA del PE y se descifra antes de calcular la etiqueta.",
            "B":"Los QWORD iniciales de keybank en disco son el estado final usado por stream_tag.",
            "C":"El valor de decoy_checksum es el que se imprime como resultado principal.",
            "D":"La longitud, la posición y el valor de cada byte influyen en el cálculo.",
            "E":"El recurso RCDATA 702 reemplaza obligatoriamente la tabla antes de printf."
        }, points=8),
    ], {"q1":a(stream_info["program"],"Seguir la carga de RCDATA, descifrar 16 claves y reconstruir las actualizaciones dependientes de byte e índice; comparar con 384 entradas ocultas."),
        "q2":a(hex(stream_info["function_rva"]),"Seguir el valor que llega a printf; decoy_checksum solo actualiza un sink diagnóstico."),
        "q3":a(hex(stream_info["resource_id"]),"FindResourceA selecciona el identificador 701; el 702 es un recurso señuelo."),
        "q4":a(hex(stream_info["key0"]),"Descifrar la primera entrada del recurso RCDATA mediante el estado inicial de load_keys."),
        "q5":a(hex(stream_info["empty"]),"Con n=0 no se ejecuta el bucle; se combinan los estados iniciales y k[0]."),
        "q6":a(hex(stream_info["sample"]),"Evaluar la transformación real o consultar el oráculo con los 16 bytes."),
        "q7":a(["A", "D"],"El recurso 701 aporta las claves y la iteración depende de n, i y byte; los señuelos no determinan el valor impreso.")},
    track="research")
CASES[-1]["artifacts"].append("artifacts/hard_stream/stream_oracle.exe")

repair_info = build_repair()
repair_expected = {"sites": repair_info["canonical"]["sites"], "versions": [
    {"path": str(item["exe"].relative_to(ROOT)).replace("\\", "/"),
     "length_rva": hex(item["len_rva"]), "flag_rva": hex(item["flag_rva"])}
    for item in repair_info["versions"]],
    "tests": [{"x": hex(x), "y": hex(y),
               "output": "ACCEPT" if repair_accepted(x, y) else "REJECT"}
              for x, y in repair_vectors()]}
repair_samples = [(0, 0), (0, 0x20), (0, 0x21), (1, 0x20), (1, 0x21),
                  (0xFF, 0x21), (0x100, 0x20), (0x100, 0x21), (0x101, 0x21),
                  (0x80, 0x20), (0x80, 0)]
add("hard_repair_aob", "Reparar dos saltos de control en cuatro builds PE64", "Parche binario y patrones PE", "extremo+++",
    "Tres versiones sin símbolos de la misma utilidad aceptan o rechazan pares uint64. Cada versión "
    "contiene exactamente dos defectos de un byte en saltos condicionales cortos. Debes derivar "
    "una firma de localización para cada salto y el byte de reemplazo; el corrector aplicará ambas "
    "reparaciones a las tres versiones visibles y a una cuarta compilación oculta con otra disposición "
    "de código. Los pares de entrada ocultos comprueban que se aceptan los válidos y se rechazan "
    "los inválidos. No se entrega fuente ni PDB.",
    {"brief.txt": """
Uso: repair_vN.exe 0xX 0xY
Salida: ACCEPT o REJECT. Los tres ejecutables visibles comparten el mismo
contrato de aceptación. Una rutina de auditoría usa x,y, pero no decide la salida.

Solo se permiten DOS cambios de un byte, ambos en opcodes de saltos condicionales
cortos de la función que decide ACCEPT/REJECT. Conserva los desplazamientos y los
demás bytes. La cuarta build no se entrega. Tu patrón de cada sitio debe encontrar
una sola coincidencia en .text de cada build, visible y oculta, y el `offset`
debe señalar exactamente el opcode que se cambia.

Formato de answers.q1:
{"sites":{"length":{"pattern":"TOKENS AOB","offset":0,"byte":"HH"},
          "flag":{"pattern":"TOKENS AOB","offset":0,"byte":"HH"}}}
El ejemplo muestra campos, no valores de solución. Cada patrón tiene 8..64 tokens
separados por espacio, cada token `HH` o `??`, al menos 8 bytes literales.
`offset` es la posición 0-based del opcode dentro del patrón; `byte` son dos
dígitos hexadecimales del nuevo opcode. El corrector prueba las firmas en cuatro
builds y ejecuta los PE reparados con entradas ocultas. Solo se admiten los
opcodes de salto condicional esperados en los sitios comprobados.
""",
     "expected_samples.txt": "Valores del contrato correcto (antes de puntuar, no del binario defectuoso):\n" +
     "\n".join(f"x={x:#x} y={y:#x} => {'ACCEPT' if repair_accepted(x, y) else 'REJECT'}"
               for x, y in repair_samples)}, [
        q("q1", "patch_aob", "Devuelve las dos firmas y bytes de reparación que funcionan en las cuatro builds.", points=120),
        q("q2", "hex", "RVA de comienzo de la rutina que decide ACCEPT/REJECT en repair_v1.exe.", points=8),
        q("q3", "hex", "RVA del opcode defectuoso que controla el límite de x en repair_v2.exe.", points=8),
        q("q4", "hex", "RVA del opcode defectuoso que controla el bit de y en repair_v3.exe.", points=8),
        q("q5", "single", "Tras reparar, ¿qué debe imprimir x=0x100, y=0x20?", {
            "A":"ACCEPT", "B":"REJECT", "C":"ERROR", "D":"La salida depende de la build."
        }, points=4),
        q("q6", "single", "Tras reparar, ¿qué debe imprimir x=0, y=0?", {
            "A":"ACCEPT", "B":"REJECT", "C":"ERROR", "D":"La salida depende de la build."
        }, points=4),
        q("q7", "multi", "Selecciona las propiedades que exige una reparación válida.", {
            "A":"El patrón de cada sitio tiene una coincidencia única en .text de cada build.",
            "B":"Se puede cambiar el desplazamiento relativo de ambos saltos para llamar a la auditoría.",
            "C":"La reparación debe conservar tanto aceptaciones correctas como rechazos correctos.",
            "D":"Basta con acertar el RVA absoluto de repair_v1 para localizar la cuarta build.",
            "E":"Cada `offset` señala el byte del opcode que cambia, no la instrucción siguiente."
        }, points=8),
    ], {"q1":a(repair_expected,"Localizar los dos JCC defectuosos, crear firmas únicas entre builds, reemplazar solo sus opcodes y validar la función reparada con entradas ocultas."),
        "q2":a(hex(repair_info["versions"][0]["function_rva"]),"Seguir la llamada desde main hasta la rutina que decide el texto impreso."),
        "q3":a(hex(repair_info["versions"][1]["len_rva"]),"El primer salto corto tras comparar x con 0x100 es inclusivo por error."),
        "q4":a(hex(repair_info["versions"][2]["flag_rva"]),"El salto que sigue a TEST del bit 0x20 tiene la polaridad equivocada."),
        "q5":a("A","El límite x=0x100 es válido y el bit requerido de y está presente."),
        "q6":a("B","Sin el bit requerido de y debe rechazarse."),
        "q7":a(["A", "C", "E"],"Las firmas deben ser únicas, señalar el opcode y conservar las decisiones positivas y negativas correctas.")},
    track="research")
KEY["hard_repair_aob"]["q1"]["canonical_patch"] = repair_info["canonical"]
CASES[-1]["artifacts"].extend(f"artifacts/hard_repair/repair_v{version}.exe" for version in (1, 2, 3))

stream2_info = build_stream2()
add("hard_tls_stream2", "Recuperar dos recorridos de un mensaje con claves iniciadas en TLS",
    "TLS, recursos PE y RE funcional", "extremo++++",
    "Un PE64 sin PDB acepta mensajes hexadecimales de 0 a 96 bytes y devuelve una etiqueta de "
    "64 bits. Las claves efectivas no están en claro en el archivo: un callback TLS lee un recurso "
    "RCDATA y las descifra antes de main. La rutina que imprime el resultado hace dos recorridos "
    "dependientes del contenido, uno en cada dirección. Hay un recurso y una rutina de auditoría "
    "que no determinan la salida principal. Recupera el comportamiento para mensajes no vistos; "
    "el corrector usa 384 entradas ocultas, incluidas longitudes frontera y clases de bytes distintas.",
    {"brief.txt": """
Uso: stream2_oracle.exe HEX, o stream2_oracle.exe - para el mensaje vacío.
Salida: 16 dígitos hexadecimales. El ejecutable es PE64 sin PDB.
La entrada se limita a 96 bytes. El ejecutable puede consultarse como oráculo,
pero las 384 pruebas de q1 no se entregan. Se requiere reconstruir ambos
recorridos y el estado efectivo que el cargador establece antes de main.
""",
     "dsl.txt": """
Formato de answers.q1: objeto JSON con `tables`, `steps` y `return`.
Registros iniciales: `x=0`, `y=0`, `n` = longitud del mensaje. Destinos
libres con nombre alfanumérico; no se puede asignar a x,y,n,i,byte.
Los operandos son registros definidos, enteros o constantes `0x...`.
Todas las operaciones se calculan módulo 2^64.

Operaciones: add, sub, xor, and, or, mul (a,b); rol, ror, shl, shr (a,bits);
not (a); sel (cond,a,b), que elige a cuando cond != 0; lookup
(table,index), con índice módulo longitud de la tabla.
Hasta cuatro tablas, cada una de hasta 16 uint64. `steps` admite hasta 64
instrucciones. `each` ejecuta `body` en orden creciente de índice; `each_reverse`
lo ejecuta en orden decreciente. Dentro del cuerpo están disponibles `i` y
`byte`. Cada cuerpo admite hasta 32 instrucciones. Ambos bucles pueden compartir
los registros calculados antes o durante el otro bucle. Sin bucles anidados.
Máximo 8192 instrucciones ejecutadas por entrada; se incluye el mensaje vacío.

Ejemplo de sintaxis, NO es la solución:
{"tables":{"k":["0x5"]},"steps":[
  {"dst":"acc","op":"xor","a":"n","b":"0x5"},
  {"op":"each","body":[{"dst":"acc","op":"add","a":"acc","b":"byte"}]},
  {"op":"each_reverse","body":[{"dst":"acc","op":"xor","a":"acc","b":"i"}]}
],"return":"acc"}

Devuelve el objeto en answers.q1, no código ejecutable ni una cadena JSON.
"""}, [
        q("q1", "stream2_64", "Reconstruye la etiqueta completa como programa DSL para cualquier mensaje válido.", points=300),
        q("q2", "hex", "RVA inicial de la función que genera la etiqueta impresa.", points=8),
        q("q3", "hex", "RVA del callback TLS que inicializa las claves efectivas.", points=8),
        q("q4", "hex", "Identificador del recurso RCDATA usado por el callback TLS.", points=8),
        q("q5", "hex", "Primer uint64 de la tabla de claves efectiva, después de descifrarla.", points=10),
        q("q6", "hex", "Etiqueta para el mensaje vacío.", points=6),
        q("q7", "hex", "Etiqueta para 00112233445566778899AABBCCDDEEFF.", points=6),
        q("q8", "multi", "Selecciona todas las afirmaciones correctas sobre la salida principal.", {
            "A":"El callback TLS modifica el estado antes de entrar en main.",
            "B":"El recurso RCDATA 804 suministra necesariamente las claves efectivas.",
            "C":"El segundo recorrido procesa los bytes desde el último hasta el primero.",
            "D":"La función de auditoría, y no la de dos recorridos, alimenta printf.",
            "E":"El resultado para un mensaje de 16 bytes puede inferirse del mensaje vacío sin analizar los bucles."
        }, points=4),
    ], {"q1":a(stream2_info["program"], "Descifrar el RCDATA 803 desde el callback TLS, reconstruir ambos recorridos y contrastar la etiqueta en 384 mensajes ocultos."),
        "q2":a(hex(stream2_info["function_rva"]), "Seguir el valor entregado al printf hasta two_pass_tag."),
        "q3":a(hex(stream2_info["callback_rva"]), "Leer el directorio TLS del PE y resolver el VA del callback."),
        "q4":a(hex(stream2_info["resource_id"]), "FindResourceA selecciona 803; 804 es un señuelo."),
        "q5":a(hex(stream2_info["key0"]), "Aplicar el descifrado del callback a la primera entrada RCDATA."),
        "q6":a(hex(stream2_info["empty"]), "Los dos recorridos omiten su cuerpo si n=0."),
        "q7":a(hex(stream2_info["sample"]), "Ejecutar el oráculo o evaluar ambos recorridos con las claves efectivas."),
        "q8":a(["A", "C"], "TLS inicializa las claves y el segundo bucle recorre índices decrecientes.")},
    track="research")
CASES[-1]["artifacts"].append("artifacts/hard_stream2/stream2_oracle.exe")

dump_info = build_dump()
add("hard_crash_dump", "Diagnosticar un acceso inválido desde un minidump x64 real",
    "Minidump, excepción y pila x64", "extremo++++",
    "Un proceso PE64 falló al consumir un búfer. Se entrega el ejecutable sin PDB y un minidump "
    "capturado durante la excepción, con contexto de hilo, módulos y memoria privada. Determina "
    "el acceso que falló, recupera el puntero que se pretendía usar y explica la pérdida de bits. "
    "Para el resultado contrafáctico, conserva el resto del programa y corrige únicamente esa "
    "pérdida de bits. Usa el volcado entregado como evidencia autoritativa; una nueva ejecución "
    "puede tener distinta base de imagen por ASLR.",
    {"brief.txt": """
Artefactos: dump_probe.exe y fault.dmp. El segundo es un minidump genuino
escrito por MiniDumpWriteDump durante la excepción del ejecutable adjunto.
No se entrega PDB ni código fuente. No necesitas ejecutar de nuevo el PE.

Las preguntas sobre direcciones VA se refieren al proceso capturado en fault.dmp.
Las RVA son relativas a la base del módulo dump_probe.exe dentro de ese dump.
`encoded_payload` guarda un puntero de 64 bits ofuscado por XOR; una función de
auditoría accede correctamente al mismo búfer antes del fallo. El camino que
falla pasa por dispatch_job, resolve_payload y consume_payload.

Puedes parsear los streams MINIDUMP_EXCEPTION_STREAM, MINIDUMP_MODULE_LIST y
MINIDUMP_MEMORY_LIST con Python, o usar herramientas de depuración locales.
Para el resultado tras la corrección, usa el contenido del búfer capturado.
"""}, [
        q("q1", "hex", "Código NTSTATUS de la excepción registrada en el minidump.", points=8),
        q("q2", "hex", "RVA exacta de la instrucción que causó la excepción.", points=10),
        q("q3", "hex", "VA exacta que intentó leer esa instrucción.", points=10),
        q("q4", "single", "¿Qué clase de acceso indica ExceptionInformation[0]?", {
            "A":"Lectura", "B":"Escritura", "C":"Ejecución", "D":"Violación de pila"
        }, points=8),
        q("q5", "hex", "VA completa del inicio del búfer que debería haber recibido consume_payload.", points=14),
        q("q6", "hex", "Valor de encoded_payload guardado en JOB en el proceso capturado.", points=12),
        q("q7", "hex", "Constante XOR usada para descodificar encoded_payload.", points=10),
        q("q8", "hex", "RVA de comienzo de resolve_payload.", points=10),
        q("q9", "hex", "RVA de comienzo de consume_payload.", points=8),
        q("q10", "hex", "Valor uint64 que devolvería dispatch_job con el mismo búfer tras conservar los 64 bits del puntero.", points=14),
        q("q11", "single", "¿Qué causa raíz explica la dirección inválida de q3?", {
            "A":"El búfer fue liberado antes de la lectura.",
            "B":"La dirección descodificada se reduce a 32 bits antes de convertirse de nuevo en puntero.",
            "C":"El callback TLS cifró los bytes del búfer.",
            "D":"La página de destino tiene PAGE_NOACCESS aunque el puntero es correcto."
        }, points=10),
        q("q12", "multi", "Selecciona los cambios que corrigen la causa sin cambiar el formato de JOB.", {
            "A":"Conservar la dirección descodificada en uintptr_t hasta convertirla en puntero.",
            "B":"Quitar la conversión intermedia a uint32_t.",
            "C":"Aplicar una segunda conversión a uint32_t antes de leer el búfer.",
            "D":"Usar encoded_payload directamente como VA sin descifrarlo.",
            "E":"Cambiar solo el byte fault.dmp de la dirección inválida."
        }, points=8),
    ], {"q1":a(hex(dump_info["exception_code"]), "MINIDUMP_EXCEPTION_STREAM contiene el código 0xC0000005."),
        "q2":a(hex(dump_info["fault_rva"]), "Restar la base del módulo al ExceptionAddress del minidump."),
        "q3":a(hex(dump_info["fault_address"]), "ExceptionInformation[1] es la VA leída, correspondiente al puntero truncado más 3."),
        "q4":a("A", "ExceptionInformation[0]=0 indica lectura en una excepción de acceso."),
        "q5":a(hex(dump_info["allocation"]), "El JOB conserva expected_payload y la auditoría desofusca el puntero completo."),
        "q6":a(hex(dump_info["encoded"]), "El JOB de la región de datos contiene allocation XOR COOKIE."),
        "q7":a(hex(dump_info["cookie"]), "La constante inmediata de la rutina que descodifica el puntero."),
        "q8":a(hex(dump_info["resolve_rva"]), "Seguir la llamada desde dispatch_job a resolve_payload."),
        "q9":a(hex(dump_info["consume_rva"]), "Seguir la llamada desde resolve_payload a la lectura que falla."),
        "q10":a(hex(dump_info["fixed_result"]), "Leer payload[3] y payload[7] del dump y propagar consume_payload, resolve_payload y dispatch_job."),
        "q11":a("B", "Un uint32_t intermedio descarta la mitad alta de la dirección válida."),
        "q12":a(["A", "B"], "Conservar los 64 bits o eliminar el estrechamiento evita usar una VA truncada.")},
    track="research")
CASES[-1]["artifacts"].extend(["artifacts/hard_dump/dump_probe.exe", "artifacts/hard_dump/fault.dmp"])

pipeline_info = pipeline_case()
add("hard_pipeline", "Recuperar función x64 para entradas ocultas", "RE funcional", "extremo+",
    "Un PE64 de consola implementa una transformación uint64_t mix_payload(uint64_t x, uint64_t y). "
    "Puedes consultarlo con dos argumentos hexadecimales, pero el test principal se evalúa en 256 "
    "pares de entrada que no se entregan. Recupera la función de su código máquina y exprésala con "
    "el DSL restringido del artefacto. Las operaciones usan aritmética modular de 64 bits.",
    {"brief.txt": """
Uso del oráculo: mix_oracle.exe 0xX 0xY
Salida: 16 dígitos hexadecimales, o error si los argumentos no son válidos.

El ejecutable es un PE64 sin PDB y contiene CRT estático. La función propia
mix_payload recibe los dos parámetros en los registros Windows x64 estándar.
No se entrega fuente. El objeto JSON de q1 se ejecutará en un intérprete seguro
sobre 256 pares ocultos, incluidos valores frontera y ambas ramas de control.
""",
     "dsl.txt": """
Formato de q1: objeto JSON con `steps` (1..32 instrucciones) y `return`.
Registros iniciales: `x` y `y` (uint64). Destinos: `r0`..`r15`.
Un operando es un registro ya definido o una constante hexadecimal `0x...`.
Cada instrucción escribe `dst`. Todas las operaciones envuelven a 64 bits.

Binarias: add, sub, xor, and, or, mul: campos `a` y `b`.
Rotación/desplazamiento: rol, ror, shl, shr: campo `a` y `bits` entero 0..63.
Selección: sel: campos `cond`, `a`, `b`; devuelve a si cond != 0, si no b.
Unaria: not: campo `a`.

Ejemplo de sintaxis (NO es la solución):
{"steps":[{"dst":"r0","op":"xor","a":"x","b":"0x5"},
          {"dst":"r1","op":"rol","a":"r0","bits":7}],"return":"r1"}

Devuelve este objeto como valor de `answers.q1`, no como texto escapado.
El corrector acepta programas equivalentes, no exige los mismos registros o
la misma secuencia de instrucciones que la implementación de referencia.
"""}, [
        q("q1", "pipeline64", "Recupera mix_payload como programa DSL que funcione para cualquier x,y uint64.", points=50),
        q("q2", "hex", "¿Cuál es el RVA inicial de mix_payload dentro del PE?", points=5),
        q("q3", "hex", "¿Qué devuelve mix_payload para x=0x0123456789ABCDEF, y=0xFEDCBA9876543210?", points=4),
        q("q4", "hex", "¿Cuál es la máscara de bits usada para elegir entre las dos ramas?", points=5),
        q("q5", "hex", "¿Cuál es la constante uint64 multiplicada por (x+y) en la combinación final?", points=5),
    ], {"q1":a(pipeline_info["program"],"Reconstruir la secuencia de operaciones y la selección condicional del código x64; se valida funcionalmente en 256 pares."),
        "q2":a(hex(pipeline_info["function_rva"]),"Seguir la llamada de main a la rutina que mezcla x e y."),
        "q3":a(hex(pipeline_info["sample"]),"Aplicar la función recuperada; también se puede contrastar con el oráculo."),
        "q4":a(hex(pipeline_info["branch_mask"]),"La condición prueba el bit 0x20 de x XOR y."),
        "q5":a(hex(0xC2B2AE3D27D4EB4F),"Constante de la multiplicación final que se combina por XOR con la rama."),
    }, track="research")
CASES[-1]["artifacts"].append("artifacts/hard_pipeline/mix_oracle.exe")

add("hard_pattern_open", "Firma AOB abierta con build oculto", "Patrones PE", "extremo+",
    "Recupera una firma de bytes para la rutina viva que lee un DWORD de la estructura en +0x2A8. "
    "Hay una rutina de auditoría que lee el mismo campo. Dispones de tres PE64 sin símbolos y "
    "el patrón se probará también en una cuarta build no entregada. La firma debe empezar en "
    "el primer byte de la rutina viva y coincidir exactamente una vez en `.text` de cada versión.",
    {"brief.txt": """
Archivos visibles: layout_v1.exe, layout_v2.exe, layout_v3.exe.
La cuarta build se mantiene fuera del entorno del agente para validar
generalización. El código de auditoría cambia de tamaño entre builds y
también lee +0x2A8; un match único no basta si señala esa rutina.

Formato de firma: tokens separados por espacios; cada token es un byte
hexadecimal de dos dígitos (`8B`) o wildcard `??`. Longitud 8..64 bytes,
al menos 8 bytes literales. El primer token representa la primera instrucción
de la rutina viva. El corrector examina solo la sección .text.
"""}, [
        q("q1", "aob", "Devuelve una firma AOB válida para las tres builds visibles y la cuarta oculta. Responde con la cadena de tokens.", points=40),
        q("q2", "hex", "RVA del primer byte de la rutina viva en layout_v1.exe.", points=5),
        q("q3", "hex", "RVA del primer byte de la rutina viva en layout_v3.exe.", points=5),
        q("q4", "single", "En v3, una instrucción usa `sub eax, inm` donde v1 usa `add eax, inm`. ¿Qué explica que ambas implementen la misma operación fuente con constantes distintas?", {
            "A":"La sección .text fue cifrada y el opcode cambia al cargarla.",
            "B":"El compilador representó una suma módulo 2^32 de constante grande como resta de su complemento a dos.",
            "C":"El campo de la estructura cambió de DWORD a QWORD.",
            "D":"El decoy parchea la instrucción de la rutina viva en ejecución.",
        }, points=6),
    ], {"q1":a({"pattern":pattern_info["pattern"], "targets":[
                {"path":f"public/artifacts/hard_pattern/layout_v{item['version']}.exe", "rva":hex(item["target_rva"])}
                for item in pattern_info["versions"]] + [
                {"path":"private/hard/hidden/layout_v4.exe", "rva":hex(pattern_info["hidden"]["target_rva"])}
            ]},"El patrón se escanea en .text de cada build y debe coincidir una sola vez exactamente en la rutina viva."),
        "q2":a(hex(pattern_info["versions"][0]["target_rva"]),"Identificar la función con XOR, aritmética y rotación, no la de auditoría."),
        "q3":a(hex(pattern_info["versions"][2]["target_rva"]),"La función viva se desplaza al crecer el decoy."),
        "q4":a("B","SUB de un complemento a dos equivale a ADD módulo 2^32.")}, track="research")
KEY["hard_pattern_open"]["q1"]["canonical_pattern"] = pattern_info["pattern"]
CASES[-1]["artifacts"].extend(f"artifacts/hard_pattern/layout_v{version}.exe" for version in (1,2,3))

for case in CASES:
    if case["difficulty"] == "difícil":
        for question in case["questions"]:
            question["points"] = 2

PUBLIC.mkdir(parents=True, exist_ok=True)
(PUBLIC / "cases.json").write_text(json.dumps({"version":"10.0", "language":"es", "cases":CASES}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
(ROOT / "private" / "answer_key.json").write_text(json.dumps(KEY, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
print(f"Built {len(CASES)} cases, {sum(len(c['questions']) for c in CASES)} questions")
