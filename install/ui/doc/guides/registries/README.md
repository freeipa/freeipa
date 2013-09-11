# Components registration and build

This document contains design of component build system.

## Build system

Build system is the core of Web UI. Its task is to create instance from components definition (spec object).

The system consists of:

* registries
* builders
* component classes for registration
* nested component specification

## Registries

We can have two types of registries:

* constructor registries
* singleton registries


## Constructor registry

Constructor registry holds information required for building an object. It's basically a map with component type as a key and `{factory, constructor, default specification}` as value. For successful registration one must provide a component type, and factory or a constructor. Default specification object is not required.

Both constructors and factories should not expect more than one parameter. The only param which they will receive is a specification object.

## Singleton registry

Singleton registry is a object which stores `[component_name, instance]` pairs. The difference between singleton registry and normal JavaScript object is that the registry is supposed to create the instance if it doesn't exist when requested.

To accomplish such task registry has to have a factory or a component constructor and a specification object available. This values might be stored in a constructor registry. Therefore singleton registry might internally contain constructor registries.

## Build

The build process has a general rule: Each component handles the build of its children. It's expected that the component knows what type of children it's supposed to contain and therefore it knows how to build them. Usually that means that it knows which builder to use.

To allow smooth transition, we need to support building object by using various methods: registry, factory and constructor. When using registry, we may also want to allow applying some defaults. Therefore spec object may contain following build related properties to tell how it should be build. Each build property should have `$` prefix to distinguish it from spec properties.

* `$type`: string - component type
* `$factory`: factory function which expects this spec. obj. as param
* `$ctor`: constructor function which expects this spec. obj. as param
* `$mixim_spec`: boolean indicating that multiple specification objects can be mixed in.
* `$pre_ops`: operations which modify spec before instantiation
* `$post_ops`: operations which modify object after instantiation


## Builder

We can see that the build process is moderately complex and therefore it should not be done by parent components. It's a task for a builder.

Additionally builder must deal with following conditions:

* to have or to not have associated constructor registry
* handle only string or a function as a spec object
* handle already built object
* handle array of spec

**Builders tasks**

1. get factory or constructor function
2. make copy of spec object
3. remove reserved properties from spec object
4. call factory|constructor with a copy of spec object as param
5. return built instance

### Get factory or constructor function

The flow depends on:

* type of spec object (object, string, function)
* presence of Constructor registry

If more than one specification is defined (type, constructor, factory) the order of precedence is:

1. factory
2. constructor
3. type (registry contain spec)
    a. factory
    b. constructor


#### Distinguishing between methods

Methods are distinguished by type of spec object or it's properties.

**Type**

* spec is string
* spec is Object and `spec.type` is string
* spec in registry is evaluated the same way except that it shouldn't contain `type` property.

**Factory**

* spec is function
* spec is Object and spec.factory is function

**Constructor**

* spec is function and with extend method (indicates that it's dojo class)
* spec is Object and `spec.constructor` is function

Builder must have a reference to Constructor registry for `Type` method to be able to build the object, otherwise it doesn't have constructor or factory available, unless builder has defaults set.

### Builder defaults

Builder can have default values for factory or constructor. It's useful for builders which specializes in building one object type. Ie. widget builder might have `text_widget` as a default.

### String modes

Builder supports two behaviors when spec is a string: `type` and `property`.

**type**

String specifies object type - default

**property**

String represents a value of spec property. Spec property is specified by `string_property` builder property. One has to make sure that builder has default factory or a constructor set when using this mode.

### Conflicts of specification objects

When spec is an Object and Constructor registry has also defined default specification object, only the supplied spec is used. This behavior might be overridden by setting `mixim_spec` attribute of supplied spec to `true`. In such case supplied spec is mixed in a default spec. Setting `mixim_spec` in default spec doesn't have any effect, it's ignored.

### Spec modification - pre_ops

pre_ops' purpose is to modify spec object. Pre_ops can be specified at locations ordered by execution order as follows:

* builder: applies to all objects
* construct registry: applies to objects with given type
* spec: applies only to the one object

#### Types of operations

Pre_op can be function, object or diff object.

**Function**

Takes two params: `spec` and `context`. Has to return `spec`. It can replace the spec by other object but it has make sure that it returns something. Returned spec will replace the previous one.

**Object**

Plain object is mixed in into spec object

**Diff object**

Diff object is applied on spec by `spec_mod` utility. Control properties are removed and then remains are mixed in into spec as if it was just plain object.

### Object modification - post_ops

post_ops are similar to pre_ops but their purpose is to modify the created object. Post_ops can only be functions and objects, no diff objects. Functions receive `obj`, `spec` and `context` as params and have to return `obj`.


## Global registries for builders and registries

Web UI has several object types: entities, facets, widgets, fields, actions, validators, entity policies, facet policies. Each object type requires its builder, construct registry and some also a singleton registry. Two umbrella pseudo-registries were created to avoid creation of twice as many modules and also to allow redefinition of the registries: `reg` and `builder`.

**`reg`**
is a registry of construct registries or singleton registries. Difference between normal registry is that one can access its registries directly.

**`builder`**
is a registry of builders. Each object type may have its own builder with different defaults, pre_ops, post_ops and construct registry. Construct registry is usually the one registered in `reg` under the same type name.
Builder also serves as general build interface so one don't have to obtain the builder first. It's interface is:

    var new_obj = builder.build(object_type, spec, context, overrides);

`builder` contains general builder - a builder without any defaults. It can be used when there is a need to use builder logic but it doesn't require any defaults:

    var new_obj = builder.build('', spec, context, overrides);

## Examples

For demonstration purposes examples will use action as a framework object

### Registration of builder and registry to global registries


    // './facet_registry.js'
    define(['./builder', './reg'], function(builder, reg) {

        var  exp = {};

        var exp.action = function(spec) {
            //fac definition
        };

        // Registration of Action builder and registry into global registries
        // ./builder can create new builder just by calling `get` with
        // not-yet-registered type
        exp.action_builder = builder.get('action');

        // setting default factory
        exp.action_builder.factory = exp.action;

        // registration of construct registry - builder by default creates its
        // own construct registry
        reg.set('action', exp.action_builder.registry);

        return exp;
    });


#### Singleton registry

Some object types, like entities, are singletons. It's type corresponds to instance. For these types the registration is slightly different:

    define(['./_base/Singleton_registry','./builder', './reg'],
            function(Singleton_registry, builder, reg) {

        var  exp = {};
        // module definition ...

        // registries definition
        var registry = new Singleton_registry();
        reg.set('entity', registry);
        builder.set('entity', registry.builder);
        registry.builder.factory = exp.entity;

        return exp;
    });


### New action registration

    define([
            './phases',
            './reg'
        ], function(phases, reg) {
        var exp = {};
        exp.custom_action = function(spec) { /* definition */ };

        exp.registry = function() {
            var a = reg.action; // action construct registry
            a.register('custom', exp.custom_action);
        };

        // register in registration phase
        phases.on('registration', exp.registry);
        return exp;
    });


### Build of new action

    define([
            './builder'
        ], function(builder) {
        var action = builder.build('action', {
            $type = 'custom'
            /* other spec properties */
        }); // no context and no overrides

        // simplified:
        action = builder.build('action', 'custom');
    });


### Raw usage of Singleton registry without using global registries

It's only example. One should use global registries for facets and entities.

#### Definition

    // './facet_registry.js'
    define(['./_base/Singleton_registry'], function(Singleton_registry) {

        return new Singleton_registry();
    });

#### Usage

    define(['./facet_registry', './ipa'], function(registry, IPA) {

        var my_facet = function(spec) {

            spec = spec || {};

            var that = IPA.facet(spec);
            return that;
        };

        // optional, but for facets preferable
        var default_spec = { /* some properties */ };

        // register factory as construct specification
        registry.register('foo_facet', my_facet, default_spec);


        // we may define other instance with the same factory
        var other_spec = { /* other properties */ };

        // register with spec object
        registry.register({
            type: 'other_facet',
            factory: my_facet,
            spec: other_spec
        });

        // obtaining instance
        var foo_facet = registry.get('foo_facet');
        var other_facet = registry.get('other_facet');
    });
