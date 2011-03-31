/*jsl:import ipa.js */

if (window.location.protocol == 'file:') {
    IPA.json_url = "test/data";
    IPA.use_static_files = true;

    IPA.details_refresh_devel_hook = function(entity_name,command,pkey){
        if ((entity_name === 'host')||(entity_name === 'permission')){
            command.name =   entity_name+'_show_'+pkey;
            command.method = entity_name+'_show';
        }
    };
}
