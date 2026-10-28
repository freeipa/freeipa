# Introduction

Declarative nature and support for extensibility of FreeIPA WebUI
creates demand for structural initialization of the application. Phase
components were created to solve this tasks.

## Components

Phases functionality consists of the two components/modules:
`./_base/PhaseController` and `./phases`.

### PhaseController

Phase controller basically does all the work. It provides functionality for running and
changing phases.

-   define phases
-   controls instantiation of PhaseController
-   provides API for phase task registration

## Phase

Phase is a part of application runtime. Most of the phases are related
to load and initialization process.

### Tasks

Phase consists of task. Each task can have a priority set, 10 is
default. Task can by synchronous or asynchronous. When phase is started
it runs all tasks sequentially sorted by priority. If the task is
synchronous it waits for its completion before starting another task.
Asynchronous task are just started. Phase is completed when all task
finishes - waits for all asynchronous tasks.

Asynchronous task is a task which handler returns a promise.

### Phase task registration

Modules should register a phase task through `./phases` module.

    phases.on('phase_name', handler, priority);

## Descriptions of FreeIPA phases

FreeIPA has following phases:

-   customization
-   registration
-   init
-   metadata
-   post-metadata
-   profile
-   runtime
-   shutdown

### Resource load implicit phase

Each application needs to load its resources. This mainly means
JavaScript files but also CSS files, images and fonts. Phases modules
are part of that data and therefore are no initialized until loaded.
Hence resources load is an implicit and a first phase.

FreeIPA Web UI uses AMD modules therefore resources have to be either
declared in main HTML file’s header or in modules specification. The
former one is obsolete and should be replace by the latter.

The main HTML file should require an application module. Application
module is a module that should have dependencies required for the
application to run. By specifying these dependencies we may control
which modules/plugins and their dependencies get loaded. Currently it’s
`freeipa/app`.

### Alternation phase

Serves for altering components specifications. This phase should be used
only by plugins and configurable modules. Core modules shouldn’t use
this phase.

### Registration phase

Modules should register widget, facet, entity final construct
specifications.

### Init phase

Serves for initialization of core UI components: application controller,
router, menu, application widget …

### Metadata phase

Metadata, configuration and user specific information should be loaded
in this phase.

### Runtime phase

Phase where plugins can expect that application is completely
initialized. Most of user interaction will happen here.

### Shutdown phase

Destroys session. Currently redirects to other page. In future may
destroy all facets and entities and just show basic UI again.

## Adding a new phase

One can add a new phase at any time. It will be executed only if it’s
position is after currently running phase.


    define(['./phases'], function(phases) {

        // add 'new-phase' on the last position
        phases.add('new-phase');

        // add 'pre-runtime' phase before 'runtime' phase
        phases.add('pre-runtime', { before: 'runtime' });

        // add 'post-runtime' phase after 'runtime' phase
        phases.add('post-runtime', { after: 'runtime' });

        // add '7th-phase' phase on exact position (whatever it is)
        // or on the last, if position is bigger than number of currently
        // registered phases
        phases.add('7th-phase', { position: 7 });
    });
