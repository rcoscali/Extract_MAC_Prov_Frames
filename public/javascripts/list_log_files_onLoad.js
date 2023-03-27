/*
 * Event handler for checkboxes (onclick)
 */

// Event handler for checkbox allowing to process secured frames
var onSecuredFrameExtract =
    (i) =>
    {
        document.location.href = '/extract_secured_mac_frames/' + log_files_tbl[i]['id'];
    }

// Event handler for checkbox allowing to process provisionning frames
var onProvFrameExtract =
    (i) =>
    {
        document.location.href = '/extract_mac_frames/' + log_files_tbl[i]['id'];
    }

// Event handler for checkbox allowing to list secured frames
var onListSecuredFrame =
    (i) =>
    {
        document.location.href = '/list_secured_frames/' + log_files_tbl[i]['id'];
    }

// Event handler for checkbox allowing to list provisionning frames
var onListProvFrame =
    (i) =>
    {
        document.location.href = '/list_mac_prov_frame/' + log_files_tbl[i]['id'];
    }

// Event handler for the page onload event (set from the body tag)
var localOnLoad =
    () =>
    {
        for (var i = log_files_tbl.length-1; i >= 0; i--)
        {
            /* Add a row in the table for this log file */
            var newRow = logFilesTbl.insertRow(1); 
            // Add a column for the Name of the log file
            var newCell = newRow.insertCell(0);
            // Create a link
            var link = document.createElement("a");
            // Create href attribute
            var href = document.createAttribute("href");
            // Set href value
            href.value = (log_files_tbl[i]['ProvFramesExtracted'] ? '/list_mac_prov_frame/' : '/extract_mac_frames/') + log_files_tbl[i]['id'];
            link.setAttributeNode(href);
            link.innerHTML = log_files_tbl[i]['Name'];
            newCell.innerHTML = link.outerHTML;
            // Add a column for the LogDate of the log file
            newCell = newRow.insertCell(1);
            newCell.innerHTML = log_files_tbl[i]['LogDate'];
            // Add a column for the ImportDate of the log file
            newCell = newRow.insertCell(2);
            newCell.innerHTML = log_files_tbl[i]['ImportDate'];
            // Add a column for the Version of the log file
            newCell = newRow.insertCell(3);
            newCell.innerHTML = log_files_tbl[i]['Version'];
            // Add a column for the Size of the log file
            newCell = newRow.insertCell(4);
            if (log_files_tbl[i]['Size'] !== undefined)
            {
                if (log_files_tbl[i]['Size'] > (1024*1024*1024))
                    newCell.innerHTML = (log_files_tbl[i]['Size'] / (1024*1024*1024)).toFixed(2) + " Go";
                else if (log_files_tbl[i]['Size'] > (1024*1024))
                    newCell.innerHTML = (log_files_tbl[i]['Size'] / (1024*1024)).toFixed(2) + " Mo";
                else if (log_files_tbl[i]['Size'] > 1024)
                    newCell.innerHTML = (log_files_tbl[i]['Size'] / 1024).toFixed(2) + " Ko";
                else if (log_files_tbl[i]['Size'] < 1024)
                    newCell.innerHTML = log_files_tbl[i]['Size'];
            }
            else
                    newCell.innerHTML = '?';
            // Add a column for the LinesNb of the log file
            newCell = newRow.insertCell(5);
            newCell.innerHTML = log_files_tbl[i]['LinesNb'];
            // Add a column for the UUID of the log file
            newCell = newRow.insertCell(6);
            newCell.innerHTML = log_files_tbl[i]['UUID'];
            // Add a column for the ProvFramesExtracted of the log file
            newCell = newRow.insertCell(7);
            var inputelem = document.createElement("input"); 
            var typeatttr = document.createAttribute("type");
            typeatttr.value = "checkbox";
            inputelem.setAttributeNode(typeatttr);
            if (log_files_tbl[i]['ProvFramesExtracted'])
            {
                var checkedattr = document.createAttribute("checked");
                inputelem.setAttributeNode(checkedattr);
                var roattr = document.createAttribute("readonly");
                inputelem.setAttributeNode(roattr);
                var onclickattr = document.createAttribute("onclick");
                onclickattr.value = "this.checked=!this.checked; onListProvFrame(" + i + ")";
                inputelem.setAttributeNode(onclickattr);
            }
            else
            {
                var onclickattr = document.createAttribute("onclick");
                onclickattr.value = "onProvFrameExtract(" + i +")";
                inputelem.setAttributeNode(onclickattr);
            }
            newCell.appendChild(inputelem);
            // Add a column for the ProvFramesExtracted of the log file
            newCell = newRow.insertCell(8);
            var inputelem = document.createElement("input"); 
            var typeatttr = document.createAttribute("type");
            typeatttr.value = "checkbox";
            inputelem.setAttributeNode(typeatttr);
            if (log_files_tbl[i]['SecuredFramesExtracted'])
            {
                var checkedattr = document.createAttribute("checked");
                inputelem.setAttributeNode(checkedattr);
                var roattr = document.createAttribute("readonly");
                inputelem.setAttributeNode(roattr);
                var onclickattr = document.createAttribute("onclick");
                onclickattr.value = "this.checked=!this.checked; onListSecuredFrame(" + i + ")";
                inputelem.setAttributeNode(onclickattr);
            }
            else
            {
                var onclickattr = document.createAttribute("onclick");
                onclickattr.value = "onSecuredFrameExtract(" + i +")";
                inputelem.setAttributeNode(onclickattr);
            }
            newCell.appendChild(inputelem);
        }
        document.getElementById('k_mac_ecu').value = active_keys['kMacEcu'];
        document.getElementById('k_master_ecu').value = active_keys['kMasterEcu'];
    }    

