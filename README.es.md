# linaudit

**Auditoría de seguridad de solo lectura para Linux, con un puntaje de 1 a 10.**

[Read in English](README.md) · Más información: **<https://lexiworks.dev/linaudit>**

linaudit mira tu máquina Linux como lo haría un atacante o un auditor, y te dice en palabras simples qué está mal,
qué tan grave es y cómo arreglarlo. Funciona en Debian, Ubuntu, RHEL y sus derivadas.

- **Más de 100 controles en 9 categorías**: cuentas y sudo, SSH, permisos de archivos, contraseñas y claves en texto
  plano, red y firewall, actualizaciones, indicios de compromiso, endurecimiento del sistema y aplicaciones de
  servidor habituales (Tomcat, Redis, Docker, PostgreSQL, Samba, Apache, nginx).
- **Un puntaje de 1 (peor) a 10 (mejor)** fácil de comparar entre máquinas, y los hallazgos ordenados por gravedad,
  cada uno con el comando o la configuración que lo arregla.
- **Se puede correr en cualquier lado**: nunca cambia nada del sistema, y cuando encuentra una contraseña o una clave
  solo te dice *dónde* está, nunca su valor.
- **Una interfaz de terminal cómoda**, además de un reporte de texto y salida JSON para scripts y monitoreo.
- **En castellano y en inglés.**

## Instalación

**Debian y derivadas** (en camino al archivo de Debian):

```bash
sudo apt install linaudit
```

**Gestor de paquetes Nix** (con los flakes habilitados):
```bash
# Rama main
sudo nix run github:alexiarstein/linaudit

# Otra rama
sudo nix run github:alexiarstein/linaudit/<rama>
```

**Desde el código fuente** (hace falta Rust 1.85 o más nuevo):

```bash
git clone https://github.com/alexiarstein/linaudit
cd linaudit
cargo build --release
sudo install -m 755 target/release/linaudit /usr/local/bin/
```

## Cómo se usa

```bash
sudo linaudit
```

La primera vez, linaudit te pregunta en qué idioma lo querés. Después muestra los datos de tu sistema, te pregunta qué
tipo de máquina es (un servidor, una computadora de escritorio o notebook, o un contenedor) y arranca la auditoría. Al
terminar tenés tres pestañas:

- **Resumen**: tu puntaje, los hallazgos abiertos por gravedad y los más urgentes.
- **Hallazgos**: cada problema con su detalle y cómo arreglarlo. Podés filtrar por gravedad o categoría, buscar y
  copiar el arreglo con `y`.
- **Categorías**: cómo está cada área.

Con `?` ves los atajos de teclado en cualquier momento, y con `q` salís.

> **Correlo con `sudo`.** Sin root, muchos controles no pueden leer lo que necesitan (por ejemplo, la base de
> contraseñas o las reglas del firewall). linaudit igual corre, pero te avisa qué controles no pudo evaluar y el
> puntaje no puede pasar de 6.

### Otras formas de correrlo

```bash
sudo linaudit --plain                  # reporte de texto en vez de la interfaz interactiva
sudo linaudit --plain --all            # incluye también los controles aprobados
sudo linaudit --fast                   # saltea los barridos completos del disco: segundos en vez de minutos
sudo linaudit --category ssh,accounts  # solo algunas categorías
sudo linaudit --profile server         # sin la pregunta sobre el tipo de máquina
sudo linaudit --json --output reporte.json
sudo linaudit --min-score 7            # código de salida 1 si el puntaje es menor que 7 (para cron, CI, monitoreo)
```

Todas las opciones están en `linaudit --help` y en `man linaudit`.

## Perfiles: servidor, escritorio o contenedor

No todos los controles tienen sentido en todas las máquinas. Un banner legal al iniciar sesión importa en un servidor
corporativo, no en tu notebook; el firewall de un contenedor lo maneja su host. El perfil adapta el criterio:

| Perfil | Para | Qué cambia |
|---|---|---|
| `server` | servidores, VPS, todo lo expuesto | nada: todos los controles con su gravedad completa |
| `desktop` | computadoras personales | relaja los controles pensados para servidores corporativos y baja el del firewall de ALTO a MEDIO |
| `container` | contenedores y VMs efímeras | lo que maneja el host (reloj, firewall, kernel, logs) queda como "no aplica" |

linaudit detecta el que corresponde y te lo sugiere. Un perfil nunca esconde un control: solo le cambia la gravedad o
lo marca como "no aplica", y lo deja escrito en el reporte.

## Cómo se calcula el puntaje

Cada control pesa según su gravedad (crítica, alta, media, baja). Los aprobados suman puntos, las advertencias la
mitad, las fallas nada, y el resultado se lleva a una escala de 1 a 10. Después se limita según lo que siga abierto:
con un hallazgo crítico el puntaje no puede pasar de 6, con dos no puede pasar de 4, y así, porque un "9 de 10" con un
agujero crítico abierto sería mentira. Lo que no se pudo evaluar nunca cuenta como bien.

## Aceptar un hallazgo a propósito

A veces un hallazgo es una decisión tomada: por ejemplo, la máquina está protegida por un firewall dedicado delante.
Anotalo en `/etc/linaudit/waivers.conf`, una línea por control, con el motivo:

```
NET-001   # Firewall perimetral dedicado. Ticket INF-1234
```

Un control con excepción deja de afectar el puntaje y sigue apareciendo en el reporte con su motivo, así la decisión
queda a la vista.

## Idioma

linaudit habla castellano e inglés. Pregunta una sola vez, la primera vez que lo abrís, y recuerda tu elección en
`~/.config/linaudit/config.toml`. **Para volver a elegir, borrá ese archivo** (o apretá `i` en la pantalla de
bienvenida). Para una sola corrida o en scripts, usá `--lang es` / `--lang en` o la variable `LINAUDIT_LANG`.

## Auditorías semanales

El paquete de Debian incluye un timer de systemd que corre la auditoría una vez por semana y guarda el último reporte
en `/var/lib/linaudit/latest.json`. Viene apagado; para activarlo:

```bash
sudo systemctl enable --now linaudit.timer
```

## Para tener en cuenta

- Los reportes describen los puntos débiles de tu máquina: guardalos en privado.
- Algunos controles son heurísticos y pueden dar falsos positivos, sobre todo la búsqueda de contraseñas en archivos.
  Tomá los hallazgos como cosas para revisar, no como veredictos.
- linaudit no reemplaza una auditoría formal de cumplimiento (CIS, STIG), un análisis forense ni un antivirus/EDR. Es
  un chequeo de salud rápido y honesto que podés correr todas las veces que quieras.
- Los controles para la familia Red Hat (RHEL, Rocky, Alma, Fedora) están menos probados que los de Debian. Los
  reportes y pull requests son muy bienvenidos.

## Más

- Sitio y documentación: **<https://lexiworks.dev/linaudit>**
- Lista completa de controles: [docs/CHECKS.md](docs/CHECKS.md)
- Errores e ideas: <https://github.com/alexiarstein/linaudit/issues>
- Cómo colaborar (compilar, probar, traducir): [CONTRIBUTING.md](CONTRIBUTING.md)

Hecho por Alexia Michelle. Software libre bajo la [GNU AGPL v3.0 o posterior](LICENSE).
