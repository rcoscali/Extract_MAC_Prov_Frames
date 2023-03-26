var localOnLoad =
    () =>
    {
        for (var i = she_args_tbl.length-1; i >= 0; i--)
        {
            var newRow = sheCmdArgsTbl.insertRow(1); /* Add  a row for this log file */
            // Add a column for the SHE M1 cmd args of the log file
            var newCell = newRow.insertCell(0);
            // Create a link
            var link = document.createElement("a");
            var href = document.createAttribute("href");
            href.value = (she_args_tbl[i]['keysExtracted'] ? '/show_unwrapped_frame/' : '/unwrap_mac_keys_from_frame/') + she_args_tbl[i]['frameId'];
            link.setAttributeNode(href);
            link.innerHTML = she_args_tbl[i]['m2'];
            var align = document.createAttribute("align");
            align.value = "center";
            newCell.setAttributeNode(align);
            newCell.innerHTML = link.outerHTML;
            // Add a column for the KeysExtracted of the log file
            newCell = newRow.insertCell(1);
            var align = document.createAttribute("align");
            align.value = "center";
            newCell.setAttributeNode(align);
            newCell.innerHTML = '<input type="checkbox" onclick="this.checked=!this.checked;" readonly'+(she_args_tbl[i]['keysExtracted'] ? ' checked' : '')+'>&nbsp;</input>';
        }
        document.getElementById('k_mac_ecu').value = active_keys['kMacEcu'];
        document.getElementById('k_master_ecu').value = active_keys['kMasterEcu'];
    }
