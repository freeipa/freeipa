/*jsl:import ipa.js */

if (window.location.protocol == 'file:') {
    IPA.json_url = "test/data";
    IPA.use_static_files = true;
}
