/**
 *
 */
var localOnLoad =
    () =>
    {
        const para = document.createElement("p");
        const node = document.createTextNode(result_status);
        para.appendChild(node);
        document.getElementById('status').appendChild(para);
        document.getElementById('result_log').appendChild(document.createTextNode(result_log));
        document.getElementById('k_mac_ecu').value = active_keys['kMacEcu'];
        document.getElementById('k_master_ecu').value = active_keys['kMasterEcu'];
    }
