# Navigation refactoring

## Introduction

Navigation code undertook complete rewrite. Previous navigation served for multiple purposes. These purposes were so tight together that it created several limitations for future enhancements of the framework. New implementation splits the code to several more or less independent components with given responsibilities. First part of this document describes old issues, second new implementation.

## Glossary

- **navigation**: covers whole functionality of changing pages, updating of visual representation and hash.
- **menu**: only the visual representation on the page
- **hash**: part of the URL after `#` sign
- **router**: component which matches hashes to facets
- **facet**: 'page' of the application

## Problems of previous implementation

### Global state

The change of facet state was done by changing hash part of URL. The change was handled by navigation, it caused the same chain of commands as showing a different page. Basically a facet told navigation to tell it that it needs to change it state, which is redundant. The only thing needed is to announce: ``I'm changing my state''. Navigation can then just update hash.

The process was as follows:

1. `IPA.nav.push_state(state)`
2. `IPA.nav.update()`
3. `entity.display(facet_node)`
4. check if to reload facet
5. `facet.show()`
6. several calls of `IPA.nav.get_state(key)`
7. do the action

Page change was the same with some additional steps.

Using global values also prevents using more facets on a one page. Such feature is not required yet but it is an unnecessary limitation which can be easily
avoided.

### Entity structure

Menu specification and UI structure required an entity to be specified for every page. `entity.display(facet_node)` served for switching facets. The `display` method was basically doing part of a work of application controller. An artificial entity would have to be created for pages without any entity.

### Fixed dirty check

`IPA.nav.push_state(state)` method contained a code which checks facet if it has some unsaved changes (is dirty) and displays a ``dirty dialog''.  The type of the dialog was set in the method and therefore it was the same for each facet. It would create limitations for non-CRUD facets.

### DOM representation bound with rest of the functionality

This was the biggest issue. DOM representation (menu) was required for switching facets. Navigation used a concept of tabs. A tab was a node in navigation tree structure. Each leaf tab represented an entity or entity's facet. So one couldn't have a working navigation without existing menu or a facet without corresponding menu item.

### Difficult extensibility

It was very difficult to add item on particular position. The tree-like structure of tabs was hard-coded and initialized on init. Additional changes weren't supported. Navigation didn't offer any method which would add new item on certain position. Partial update of menu wasn't possible. Recreation wasn't tested.

## New implementation

Rewrite of the navigation addresses all mentioned issues. The old `IPA.navigation` class was split into server smaller ones with limited responsibilities:

* `navigation.menu_spec`
* `navigation.Menu`
* `navigation.Router`
* `Application_controller`
* `widgets.App`
* `widgets.Menu`

### Menu

Menu is implemented in two classes: `navigation.Menu` and `widgets.Menu`.

#### `navigation.Menu`

Is a data model of a menu. It contains object store of menu items. It provides array of currently selected items and events which can be used for observation of changes.

New items can be added by simple method.

#### `widgets.Menu`

Is the HTML representation of a menu - a widget. It uses `navigation.Menu` as it's data model. It listens to data model's `selected` event to update selection state and observers data.models object store to reflect it's changes. Hence, new items are immediately rendered and removed are destroyed.

Menu offers `item-select` event. Other components should listed to it and do appropriate work.

Menu widget doesn't change it's data model in any way. It just observes.

### Router

`navigation.Router` is applications router. It is an extension of dojo router. It adds a support for facets.  It provides API for route registration, hash generation and update, and navigation to facets.

IMPORTANT: Facets widgets and other parts of application shouldn't use router directly. They should use navigation proxy(`navigation`) instead.

#### Route registration

Router has `register_route(routes, handler)` method for registering of routes. It's a wrapper of Dojo's router's `register` method. The difference is that this method can  register multiple routes for one handler and that the handler is bound to router object so it can has it reference.

Standard implementation has handler for entity pages and for standalone pages. Standalone pages are not supported yet because facet register (a map of facets) is not implemented yet.

Extensions can register their own routes+handlers to support new types of facets/hash representations.

Router maintains each route registration so they can be deleted if needed.

#### Route evaluation

Evaluation is done by dojo router component. When it matches a route, it calls corresponded handler.

### Handlers and showing a facet

Route handlers receive dojo router's event argument objects. Handler can inspect old hash, new hash and state pulled from the new hash.

Handler should decode a facet and it's state, set the state to the facet and call `show_facet(facet)`. It publishes `facet-show` event. This tells the application that we should change the facet but router doesn't care how it's done.

Handler should always change if `ignore_next` flag isn't set. It can use `check_clear_ignore` which does this check and cleans the flag. When the flag is set the handler shouldn't do anything. The flag is mainly used when updating hash of already displayed facet. User can then bookmark the facet state.

### Navigating to a facet

It's a opposite operation of hash change handling and facet show. Router has two build-in methods: `navigate_to_facet` and `navigate_to_entity_facet`. Their purpose is to create hash which can be matched by some route and then call `navigate_to_hash(hash, facet)`.

**navigate_to_hash**
Tells application "I want to change facet" by raising `facet-change` global event. Listeners can inspect associated facet and hash, then set `navigation.canceled` property if they want to prevent the change. They should do it synchronously. When somebody cancels the change, navigation notifies it by raising `facet-change-canceled` global event. Otherwise the hash is updated.

#### Updating hash

Hash can be updated in two cases: navigating to a facet and updating a facet state. The difference is in setting `ignore_next` property. The former sets it, latter doesn't.


### Navigation proxy

Implemented as singleton in `.navigation` module. It's purpose is to offer interface for navigating between pages to facet, widgets and other components.

Consumers don't have to worry about internal implementation => they are not bound to specific router implementation.

Exposed methods:

* `show`
* `show_entity`
* `show_default`

Check code for arguments documentation.

Extensions can add new methods.

### Application controller

Application controller (AC) ties all the components together. It basically contains most of the integration logic as navigation did before but it delegates most of the actions to other components.

#### Application initialization

AC initialization is done in 3 phases: `app-init`, `metadata`, `profile`. Creation of AC instance and phase registration is done in `./app` module.

**app-init phase**

* creates AC instance
* create menu store
* creates router
* creates app widget
* bounds menu widget with menu store
* registers handlers for:
    * click in menu widget (`item-select` event)
    * select change in menu data model (`selected` event)
    * profile view (app widget event)
    * logout (app widget event)
    * `facet-show` (router)
    * `facet-change` (router)
    * `facet-change-canceled` (router)
* subscribes to global events (topics):
    * `phase-error`
* renders app widget

**metadata phase**
basically calls `IPA.init` to get metadata and profile information.

**profile phase**
chooses menu based on identity information obtained in metadata phase. Adds menu items to menu.

Starts the router. Start of the router causes hash evaluation. A facet is displayed when hash is specified. When no facet is displayed, AC navigates to profile's default page.

**phase error:**
When some phase fail, error content is displayed. At the time we can't count that everything is initialized so tools for displaying the error are very limited - no metadata, no profile, possibly no app widget.

#### Facet changing

AC listens to `facet-change` event. It compares current and new facet and asks old one if it is dirty, when it is, AC obtains dirty dialog from current facet and displays it. Hence, facets can choose how the dirty dialog would look like. AC prevents the change when told by the dialog.

#### Facet showing

AC hides old facets and shows new one. If new doesn't have container AC sets it one and registers listener for facet's `facet-state-change` event. At this point it also tries to identify menu item with the facet and select it. Unlike the previous implementation, it also works when no menu item is matched.

#### Menu clicks

On menu click AC tries to match facet with menu item and navigate to it.

Menu item is not selected because the change can be prevented. Therefore selection is performed in facet show handler.

#### Facet state changing

AC listens to `facet-state-change` event. AC updates hash when displayed facet changes its state.

#### Multiple menu levels

AC expect that the menu will have 2-3 menu levels. Current used CSS doesn't automatically handle 3rd level. Hence, AC observes select state and sets special class on content node to inform CSS.

#### Further generalization

As a framework class AC should be further generalized, mostly to get rid of IPA specific functions (app widget and its handlers, profiles,...).


## How does it all work together?

Now, when everything is described, we can proceed to method calls chains examples of most common use cases. It will explain what operations are executed for certain use cases.

### Loading Web UI

It just goes through `app-init`, `metadata`, `profiles` phases. At the end of profile phase a facet is selected based on hash, if there is no hash, default facet is selected. The difference is only lack of `navigate_to_xxx` call in the former case. Details will be described in following chapter.

### Navigation to a page

Initiated by:

    // navigation is './navigation' module
    var state = { key1: val1, key2: val2 };
    navigation.show(target_facet, state);

1. proxy gets reference to navigation of current AC: `nav`
2. proxy calls `nav.navigate_to_facet(facet, state);`
3. `navigate_to_facet` creates hash, calls `navigate_to_hash(facet, hash)`
4. `navigate_to_hash` ask app if it can change facet by raising `facet-change` event
5. AC will responds to it and ask current facet if it's dirty, if so:
    a. navigation is canceled. Must be canceled because it has to be synchronous and it can't wait for user input.
    b. `facet-change-cancelled` event is raised, no build in listeners for it
    c. dirty dialog is displayed
    d. user selects action
    e. on confirmation AC calls `navigate_to_hash` with same params to proceed with the change
6. hash is updated
7. hash changed event is raised and then processed by router
8. router matches hash to handler and calls handler
9. handler decodes facet and state from hash
10. handler sets state to facet, it will cause appropriate actions in facet
11. handler raises `facet-show` event
12. `facet-show` event is caught by AC (handler: `on_facet_show`)
13. AC matches facet to menu item (`this._find_menu_item(facet)`)
14. AC selects menu item (`this.menu.select(menu_item)`)
15. menu store raises `selected` event
    a. menu widget redraw itself according to selection
    b. AC adds style for third level menu if needed (handler: `on_menu_select`)
16. AC set container for facet if needed (usually for the first time)
17. AC hides current facet (`current_facet.hide()`)
18. AC shows new facet (`facet.show()`)
    * facet clears and refreshes when `needs_update()` is true (might be set by as a result of `facet.set_state(state)` call in hash handler

### Click on menu item

1. user clicks on menu item
2. raises `item-select` event of menu widget
3. AC catches it
4. AC traverse menu items to get first one with facet or entity set
5. AC calls `navigate_to_entity_facet` or `navigate_to_facet` based on the result of previous operation
6. rest is same as in [previous use case](#navigation-to-a-page)

### Update of facet state

1. facet updates its state
2. facet publishes `facet-state-change` event.
3. AC catches it and calls `navigation.create_hash` and then `navigation.update_hash`
4. facet internally responds to the change

As you can see it just updates the hash but no navigation is done. This feature makes facet independent on navigation breaks one-facet displayed limitation (there can be facet containing more facets).

### Set hash by hand in a browser when facet is dirty

Basically the same as navigation to a page, only from hash is updated step. This implementation, nor the previous one, doesn't check dirty state of currently displayed facet. Hence, facet is changed in both cases.

## Open Questions

- Should facet state update be moved from navigation to app controller?
- Add extensibility point to Menu Store for supporting initialization of different types of menu items? Extract entity & facet logic to it.
