// Local onLoad provided for each different views
// This function build the dynamic view
var localOnLoad =
    () =>
    {
        var macProvFramesTbl = document.getElementById('mac_prov_frame_tbl');
        for (var i = mac_prov_frame_tbl.length-1; i >= 0; i--)
        {
            var newRow = macProvFramesTbl.insertRow(1); /* Add  a row for this frame */
            // Add a column for the Name of the frame's log file
            var newCell = newRow.insertCell(0);
            newCell.innerHTML = mac_prov_frame_tbl[i]['name'];
            // Add a column for the Payload of the frame
            newCell = newRow.insertCell(1);
            // Create a link
            var link = document.createElement("a");
            var href = document.createAttribute("href");
            href.value = (mac_prov_frame_tbl[i]['sheCmdExtracted'] ? '/show_unwrapped_frame/' : '/unwrap_mac_keys_from_frame/') + mac_prov_frame_tbl[i]['id'];
            link.setAttributeNode(href);
            link.innerHTML = mac_prov_frame_tbl[i]['frame'];
            newCell.innerHTML = link.outerHTML;
            // Add a column for the ProvFramesExtracted of the frame file
            newCell = newRow.insertCell(2);
            newCell.innerHTML = '<input type="checkbox" onclick="this.checked=!this.checked;" readonly'+(mac_prov_frame_tbl[i]['sheCmdExtracted'] ? ' checked' : '')+'>&nbsp;</input>';
        }
        document.getElementById('k_mac_ecu').value = active_keys['kMacEcu'];
        document.getElementById('k_master_ecu').value = active_keys['kMasterEcu'];
    }
