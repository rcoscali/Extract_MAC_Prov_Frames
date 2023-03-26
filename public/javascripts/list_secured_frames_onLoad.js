var localOnLoad =
    () =>
    {
        if (cur_page > last_page)
        {
            alert('Requested page is greater than number of page available! Set to last page');
            cur_page = last_page;
            next_page = last_page;
            document.location.href = '/list_secured_frames/' + last_page;
        }
        var link_first_page = document.getElementById('link_first');
        var link_prev_page = document.getElementById('link_prev');
        var href_attr = document.createAttribute('href');
        href_attr.value = "/list_secured_frames/" + (cur_page -1);
        link_prev_page.setAttributeNode(href_attr);
        var link_cur_page_less_2 = document.getElementById('cur_page_less_2');
        var link_cur_page_less_1 = document.getElementById('cur_page_less_1');
        var input_cur_page = document.getElementById('cur_page');
        var link_cur_page_plus_1 = document.getElementById('cur_page_plus_1');
        var link_cur_page_plus_2 = document.getElementById('cur_page_plus_2');
        var link_next_page = document.getElementById('link_next'); 
        link_next_page.href = "/list_secured_frames/" + (cur_page +1);
        var link_last_page = document.getElementById('link_last');
        link_last_page.href = "/list_secured_frames/" + last_page;
        var securedFramesTbl = document.getElementById('secured_frame_tbl');
        document.getElementById('k_mac_ecu').value = active_keys['kMacEcu'];
        document.getElementById('k_master_ecu').value = active_keys['kMasterEcu'];
        link_prev_page.href="/list_secured_frames/" + prev_page;
        link_next_page.href="/list_secured_frames/" + next_page;
        if (cur_page > 2)
        {
            link_cur_page_less_2.appendChild(document.createTextNode(cur_page-2));
            href_cur_page_less_2 = document.createAttribute("href");
            href_cur_page_less_2.value = "/list_secured_frames/" + (cur_page-2);
            link_cur_page_less_2.setAttributeNode(href_cur_page_less_2);
            link_cur_page_less_1.appendChild(document.createTextNode(cur_page-1));
            href_cur_page_less_1 = document.createAttribute("href");
            href_cur_page_less_1.value = "/list_secured_frames/" + (cur_page-1);
            link_cur_page_less_1.setAttributeNode(href_cur_page_less_1);
        }
        else if (cur_page == 2)
        {
            link_cur_page_less_2.remove();
            link_cur_page_less_1.appendChild(document.createTextNode(cur_page-1));
            href_cur_page_less_1 = document.createAttribute("href");
            href_cur_page_less_1.value = "/list_secured_frames/" + (cur_page-1);
            link_cur_page_less_1.setAttributeNode(href_cur_page_less_1);
        }
        else if (cur_page == 1)
        {
            link_cur_page_less_2.remove();
            link_cur_page_less_1.remove();
        }
        input_cur_page.value=cur_page;
        if (cur_page < last_page-2)
        {
            link_cur_page_plus_1.appendChild(document.createTextNode(cur_page+1));
            href_cur_page_plus_1 = document.createAttribute("href");
            href_cur_page_plus_1.value = "/list_secured_frames/" + (cur_page+1);
            link_cur_page_plus_1.setAttributeNode(href_cur_page_plus_1);
            link_cur_page_plus_2.appendChild(document.createTextNode(cur_page+2));
            href_cur_page_plus_2 = document.createAttribute("href");
            href_cur_page_plus_2.value = "/list_secured_frames/" + (cur_page+2);
            link_cur_page_plus_2.setAttributeNode(href_cur_page_plus_2);
        }
        else if (cur_page == last_page-1)
        {
            link_cur_page_plus_1.appendChild(document.createTextNode(cur_page+1));
            href_cur_page_plus_1 = document.createAttribute("href");
            href_cur_page_plus_1.value = "/list_secured_frames/" + (cur_page+1);
            link_cur_page_plus_1.setAttributeNode(href_cur_page_plus_1);
            link_cur_page_plus_2.remove();
        }
        else if (cur_page == last_page)
        {
            link_cur_page_plus_1.remove();
            link_cur_page_plus_2.remove();
            link_next_page.remove();
            link_last_page.remove();
        }
        for (var i = 0; i < scfd_frames.length; i++)
        {
            /* Add a row in the table for this log file */
            var newRow = securedFramesTbl.insertRow(i+1); 

            // Add a column for the TimeStamp of the log file
            var newCell = newRow.insertCell(0);
            newCell.innerHTML = scfd_frames[i]['TimeStamp'];

            // Add a column for the Name of the log file
            newCell = newRow.insertCell(1);
            // Create a link
            var link = document.createElement("a");
            // Create href attribute
            var href = document.createAttribute("href");
            // Set href value
            href.value = '/compute_secured_frames_mac/' + scfd_frames[i]['id'];
            link.setAttributeNode(href);
            link.innerHTML = scfd_frames[i]['Name'];
            newCell.appendChild(link);
            // Add a column for the FrameType of the log file
            newCell = newRow.insertCell(2);
            newCell.innerHTML = scfd_frames[i]['FrameType'];
            // Add a column for the EcuName of the log file
            newCell = newRow.insertCell(3);
            newCell.innerHTML = scfd_frames[i]['EcuName'];
            // Add a column for the tMAC of the log file
            newCell = newRow.insertCell(4);
            newCell.innerHTML = scfd_frames[i]['tMAC'];
            // Add a column for the DLC of the log file
            newCell = newRow.insertCell(5);
            newCell.innerHTML = scfd_frames[i]['DLC'];
            // Add a column for the Payload of the log file
            newCell = newRow.insertCell(6);
            newCell.innerHTML = scfd_frames[i]['Payload'];
            // Add a column for the FV of the log file
            newCell = newRow.insertCell(7);
            newCell.innerHTML = scfd_frames[i]['FV'];
            // Add a column for the Msb of the log file
            newCell = newRow.insertCell(8);
            newCell.innerHTML = scfd_frames[i]['Msb'];
            // Add a column for the Lsb of the log file
            newCell = newRow.insertCell(9);
            newCell.innerHTML = scfd_frames[i]['Lsb'];
            // Add a column for the Pad of the log file
            newCell = newRow.insertCell(10);
            newCell.innerHTML = scfd_frames[i]['Pad'];
            // Add a column for the Mac of the log file
            newCell = newRow.insertCell(11);
            newCell.innerHTML = scfd_frames[i]['Mac'];
            // Add a column for the SyncFrameId of the log file
            newCell = newRow.insertCell(12);
            newCell.innerHTML = scfd_frames[i]['SyncFrameId'];
        }
    }

