#
# Copyright (C) 2020  FreeIPA Contributors see COPYING for license
#

from ipatests.test_webui.ui_driver import screenshot, UI_driver


class TestTopology(UI_driver):

    @screenshot
    def test_topology_graph(self):
        self.init_app()
        self.navigate_to_page('topology-graph')
        self.assert_visible('.topology-view')
