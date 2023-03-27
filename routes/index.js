/**
 *
 */
const os = require('os');
const express = require('express');
const router = express.Router();
const mime = require('mime');
const reader = require ("buffered-reader");
const formidable = require('formidable');
const path = require('path');
const fs = require('fs');
const stream = require('stream');
const es = require('event-stream');
const bodyParser = require("body-parser");
const sqlite3 = require('sqlite3').verbose();
const {exec} = require("child_process");
const form = formidable({uploadDir: os.tmpdir()});
const AesCmac = require('node-aes-cmac').aesCmac;
const decSHE = require('she_decrypt');
const encSHE = require('she_encrypt');
const app = require('../app');

// Constants for PATH (relative to $MAV_PROV_ROOT)
const DbLogPath = process.env.MAC_PROV_ROOT + '/var/log';
const DbDirPath = process.env.MAC_PROV_ROOT + '/var/lib';
const DbFilePath = DbDirPath + '/keystore.db';

// Instanciate keystore DB
var keystoredb =
    new sqlite3.Database(
        DbFilePath,
        sqlite3.OPEN_READWRITE | sqlite3.OPEN_FULLMUTEX | sqlite3.OPEN_PRIVATECACHE,
        (err) =>
        {
            if (err)
            {
                console.error(err.message);
                process.exit(1);
            }
            else
            {
                console.log('****** Keys DB openned, accepting requests !');

                var app = express();

                /*
                 * ========================================================================================================================= *
                 *                                                                                                                           *
                 *                                              Home page & active keys mngt                                                 *
                 *                                                                                                                           *
                 * ========================================================================================================================= *
                 */
                
                /* ========================================================================================================================= */
                /* GET home page. */
                /* ========================================================================================================================= */
                router.get(
                    '/',
                    (req, res, next) =>
                    {
                        console.log("*** GET /");
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;
                                var renderParams =
                                    {
                                        title: 'MAC Prov Tool',
                                        help: 'Tools for manipulating MAC keys, MAC provisionning CAN frames and SHE commands for Key provisionning from log files ',
                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                        accordionTab: 0
                                    }
                                res.render(
                                    'index',
                                    renderParams
                                );
                            }
                        );
                        return;
                    }
                );
                
                /* ========================================================================================================================= */
                /* GET /favicon.ico                                                                                                          */
                /* ========================================================================================================================= */
                router.get(
                    '/favicon.ico',
                    (req, res, next) =>
                    {
                        console.log("*** GET /favicon.ico");
                        var faviconOptions =
                            {
                                'root': path.join(process.env.MAC_PROV_ROOT, '/public/images'),
                                'dotfiles': 'deny',
                                'headers' :
                                {                                    
                                    'Content-Type': 'image/x-icon',
                                    'Content-Length': data.length,
                                    'X-Timestamp': Date.now(),
                                    'X-Sent': true
                                },
                                'immutable': true
                            };

                        res.sendFile(
                            'favicon.ico',
                            faviconOptions,
                            (err) =>
                            {
                                if (err)
                                {
                                    next(err);
                                    return;
                                }
                            }
                        );
                    }
                );
                                
                /*
                 * ========================================================================================================================= *
                 *                                                                                                                           *
                 *                                                     Log Files functions                                                   *
                 *                                                                                                                           *
                 * ========================================================================================================================= *
                 */
                
                /* ========================================================================================================================= */
                /* GET import_log_file. */
                /* ========================================================================================================================= */
                router.get(
                    '/import_log_file',
                    (req, res, next) =>
                    {
                        console.log("*** GET /import_log_file");
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, row) =>
                            {
                                if (row != undefined)
                                {
                                    k_mac_ecu = row.MacEcu;
                                    k_master_ecu = row.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;
                                res.render(
                                    'import_log_file',
                                    {
                                        title: 'Import a log file',
                                        help: 'Import a log file and store it in DB',
                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                        accordionTab: 0
                                    }
                                );
                            }
                        );
                    }
                );

                /* ========================================================================================================================= */
                /* POST upload_log_file */
                /* ========================================================================================================================= */
                router.post(
                    '/upload_log_file',
                    async (req, res, next) =>
                    {
                        console.log("*** POST /upload_log_file");
                        var releve, result;
                        try
                        {
                            var activeKeys = new Object;
                            var k_mac_ecu = "Not Set !";
                            var k_master_ecu = "Not Set !";
                            keystoredb.get(
                                "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                                (err, key) =>
                                {
                                    if (key != undefined)
                                    {
                                        k_mac_ecu = key.MacEcu;
                                        k_master_ecu = key.MasterEcu;
                                    }
                                    activeKeys['kMacEcu'] = k_mac_ecu;
                                    activeKeys['kMasterEcu'] = k_master_ecu;

                                    // Start upload_log_file processing
                                    form.parse(
                                        req,
                                        (err, fields, files) =>
                                        {
                                            if (err)
                                            {
                                                next(createError(err.status || 500));
                                                return;
                                            }
                                            req.fields = fields;
                                            req.files = files;
                                            
                                            var log_file = req.files.log_file;

                                            // First let's write file in DB repository
                                            var targetFilePath = DbLogPath + "/" + log_file.originalFilename;
                                            var newTargetFilePath = targetFilePath;
                                            var fileCntr = 0;
                                            var extension = path.extname(newTargetFilePath);
                                            var name = path.basename(newTargetFilePath, extension);
                                            while (fs.existsSync(newTargetFilePath))
                                            {
                                                fileCntr++;
                                                newTargetFilePath =  DbLogPath + "/" + name + '_' + fileCntr + extension;
                                            }
                                            console.log("Renaming file '"+ log_file.filepath +"' to '"+ newTargetFilePath +"'...");
                                            
                                            fs.rename(
                                                log_file.filepath,
                                                newTargetFilePath,
                                                (err) =>
                                                {
                                                    if (err)
                                                    {
                                                        console.log("Couldn't rename file " + log_file.filepath + " !");
                                                        next(err.status || 500);
                                                        return;
                                                    }
                                                    
                                                    var logdate, uuid, version;
                                                    var logdate_found = false, uuid_found = false, version_found = false;
                                                    var lines_processed = 0;
                                                    const importDateRE = /^date (?<date>.*)$/;
                                                    const uuidRE = /^\/\/ Measurement UUID: (?<uuid>[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})$/;
                                                    const versionRE = /^\/\/ version (?<version>[0-9.]+)$/;

                                                    var s =
                                                        fs.createReadStream(newTargetFilePath)
                                                        .pipe(
                                                            es.split()
                                                        )
                                                        .pipe(
                                                            es.mapSync(
                                                                (line) =>
                                                                {
                                                                    // pause the readstream
                                                                    s.pause();

                                                                    console.log("#" + lines_processed + ": " + line);
                                                            
                                                                    if (line.match(importDateRE))
                                                                    {
                                                                        var fields = importDateRE.exec(line);
                                                                        logdate = fields.groups.date;
                                                                        logdate_found = true;
                                                                    }
                                                                    if (line.match(uuidRE))
                                                                    {
                                                                        var fields = uuidRE.exec(line);
                                                                        uuid = fields.groups.uuid;
                                                                        uuid_found = true;
                                                                    }
                                                                    if (line.match(versionRE))
                                                                    {
                                                                        var fields = versionRE.exec(line);
                                                                        version = fields.groups.version;
                                                                        version_found = true;
                                                                    }
                                                                    lines_processed++;
                                                                    if ((logdate_found && uuid_found && version_found) || lines_processed > 10)
                                                                    {
                                                                        console.log("Found data for DB ... stoping ...");
                                                                        s.end();
                                                                    }
                                                                    
                                                                    // resume the readstream, possibly from a callback
                                                                    s.resume();
                                                                }
                                                            ).on(
                                                                'error',
                                                                (err) =>
                                                                {
                                                                    console.log("Error while processing '" + newTargetFilePath + "' !");
                                                                    next(err.status || 500);
                                                                    return;
                                                                }
                                                            ).on(
                                                                'end',
                                                                () =>
                                                                {
                                                                    console.log("End of initial processing for file '"+ newTargetFilePath +"'");
                                                                    keystoredb.run(
                                                                        "INSERT INTO LogFiles (Name, LogDate, ImportDate, Version, Size, UUID)   \
                                                                                VALUES        (   ?,       ?,          ?,       ?,    ?,    ?);",
                                                                        [
                                                                            path.basename(newTargetFilePath),
                                                                            logdate,
                                                                            (new Date()).toString(),
                                                                            version,
                                                                            log_file.size,
                                                                            uuid
                                                                        ],
                                                                        (err) =>
                                                                        {
                                                                            if (err)
                                                                            {
                                                                                next(err.status || 500);
                                                                                return;
                                                                            }
                                                                            
                                                                            res.render(
                                                                                'upload_log_files',
                                                                                {
                                                                                    title: 'Upload a log file',
                                                                                    help: 'Upload, process and store a log file and its parameters for further MAC Prov frames extraction',
                                                                                    content: 'File ' + log_file.originalFilename + ' uploaded successfully !',
                                                                                    activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                                                    accordionTab: 0
                                                                                }
                                                                            );
                                                                        }
                                                                    );
                                                                }
                                                            )
                                                        );
                                                }
                                            );
                                        }
                                    );
                                }
                            );
                        }
                        catch(err)
                        {
                            next(err.status || 500);
                            return;
                        }
                    }
                );
                
                /* ========================================================================================================================= */
                /* GET list_log_file.                                                                                                        */
                /* ========================================================================================================================= */
                router.get(
                    '/list_log_files',
                    (req, res, next) =>
                    {
                        console.log("*** GET /list_log_files");
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;
                                var stmt = "SELECT id, Name, LogDate, ImportDate, Version, Size, UUID, ProvFramesExtracted, SecuredFramesExtracted FROM LogFiles";
                                keystoredb.all(
                                    stmt,
                                    [],
                                    (err, rows) =>
                                    {
                                        if (err)
                                        {
                                            next(err.status || 500);
                                            return;
                                        }
                                        var renderParams =
                                            {
                                                title: 'List stored log files',
                                                help: 'List all log files imported and stored locally in DB',
                                                logfiles: {},
                                                activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                accordionTab: 0
                                            };
                                        var contentHtml = "";
                                        var firstRow = true;
                                        var lastRow = false;
                                        var index = 0;
                                        rows.forEach(
                                            (row) =>
                                            {
                                                firstRow = (index == 0);
                                                lastRow = (index == rows.length -1);
                                                contentHtml +=
                                                    (firstRow ? "[" : "")+"{id:"+row.id+","+
                                                    "Name:'"+row.Name+"',"+
                                                    "LogDate:'"+(row.logDate !== undefined ? row.LogDate.replace("'", "\'") : row.LogDate)+"',"+
                                                    "ImportDate:'"+row.ImportDate.replace("'", "\'")+"',"+
                                                    "Version:'"+row.Version+"',"+
                                                    "Size:"+row.Size+","+
                                                    "LinesNb:"+row.LinesNb+","+
                                                    "UUID:'"+row.UUID+"',"+
                                                    "ProvFramesExtracted:"+(row.ProvFramesExtracted ? "true" : "false")+","+
                                                    "SecuredFramesExtracted:"+(row.SecuredFramesExtracted ? "true" : "false")+"}"+(lastRow ? "]" : ",");
                                                index++;
                                            }
                                        );
                                        renderParams['logfiles'] = contentHtml;
                                        res.render(
                                            'list_log_files',
                                            renderParams
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
                
                /* ========================================================================================================================= */
                /* GET delete_log_files.                                                                                                     */
                /* ========================================================================================================================= */
                router.get(
                    '/delete_log_files',
                    (req, res, next) =>
                    {
                        console.log("*** GET /delete_log_files");                       
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (err)
                                {
                                    console.trace("Error on statement: SELECT MacEcu, MasterEcu FROM ActiveKeys");
                                    next(err.status || 500);
                                    return;
                                }
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;
                                keystoredb.run(
                                    "DELETE FROM LogFiles",
                                    []
                                );
                                fs.readdir(
                                    DbLogPath,
                                    (err, files) =>
                                    {
                                        if (err)
                                        {
                                            console.trace("Error while reading directory '" + DbLogPath + "'");
                                            next(err.status || 500);
                                            return;
                                        }
                                        
                                        for (const file of files)
                                        {
                                            fs.unlink(
                                                path.join(DbLogPath, file),
                                                (err) =>
                                                {
                                                    if (err)
                                                    {
                                                        console.trace("Error while unlinking file '" + path.join(DbLogPath, file) + "'");
                                                        next(err.status || 500);
                                                        return;
                                                    }
                                                }
                                            );
                                        }
                                    }
                                );
                                res.render(
                                    'delete_log_files',
                                    {
                                        title: 'Delete stored log files',
                                        help: 'Delete LOG files stored in DB (record & files)',
                                        content: 'All Log files where removed !', 
                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                        accordionTab: 0
                                    }
                                );
                            }
                        );
                    }
                );
                
                /*
                 * ========================================================================================================================= *
                 *                                                                                                                           *
                 *                                                  Processing of MAC Prov frames                                            *
                 *                                                                                                                           *
                 * ========================================================================================================================= *
                 */

                /* Closure for prov frame extraction */
                ((root) =>
                    {
                        // Prov Frame extraction processing variables
                        var index = 0;
                        var lineNr = 0;
                        var frameNr = 0;                        
                        var result_log = "";
                        var logFileName;
                        var logFileID;
                        var response;
                        
                        var provFrameRE  = /^ ? ?(?<Timestamp>[0-9.]*) (?<ProvRE>([A-Z]+)? *[12]? ?Rx *[0-9a-zA-Z]+  (?<Name>DTOOL_to_[A-Za-z0-9_]+)) +[0-9] [0-9] [a-zA-Z0-9] *(?<Data>[ 0-9a-zA-Z]+31 01 02 53[ 0-9a-zA-Z]+)   (?<Tail>(.*)(   .*))$/;
                        var provFrame = new Object;
                        var provFramesStart = new Array;
                        var parsingFrame = false;
                        var payload = "";

                        // Prov Frame Processing line handler (onLine event handler for
                        // finding a prov frame start)
                        function processProvFrames_OnLine(line)
                        {
                            // Pause emission of parsing events from stream
                            s.pause();
                            // While searching for the start of a prov frame
                            if (!parsingFrame)
                            {
                                // Find a prov frame by matching against a RegEx
                                var fields;
                                if ((fields = provFrameRE.exec(line)) != null)
                                {
                                    // Prov frame found
                                    result_log += "Found provisionning frame starting at line #" + lineNr + "\\n";
                                    var provRE = new RegExp('^ ? ?(?<Timestamp>[0-9.]*) ' + fields.groups.ProvRE + ' +[0-9] [0-9] [a-zA-Z0-9]  *(?<Data>[ 0-9a-zA-Z]+)   (?<Tail>(.*)(   .*))$');
                                    parsingFrame = true;
                                    // Preparing provFrame object used for parsing nect lines and building final frame
                                    provFrame = {
                                        index: lineNr,
                                        regex: provRE,
                                        Payload: '',
                                        Parts: new Array
                                    };
                                    // Frame part index
                                    var fix = 0;
                                    provFrame['Parts'][fix] = new Object;
                                    //if (fields.groups.Data !== undefined)
                                    //{
                                        payload = fields.groups.Data.replace(/ /g, '');
                                        provFrame['Parts'][fix]['Payload'] = payload;
                                        provFrame['Payload'] = payload;
                                    //}
                                    //console.log("Start of frame payload: " + payload);
                                    fix++;
                                }
                                lineNr++;
                                s.resume();                    
                            }
                            else
                            {
                                // Prov Frame Processing frame line handler (onLine event handler for
                                // finding prov frames following first)
                                var fields;
                                var renderParams;                            
                                                        
                                result_log += "Extracting frame #" + frameNr + " at line #" + provFrame['index'] + " with RE: /" + provFrame['regex'] + "\\n";

                                do
                                {
                                    var fields;
                                    // If line match vs a continuing prov frame
                                    if ((fields = provFrame['regex'].exec(line)) != null)
                                    {
                                        result_log += "Adding payload for frame #" + lineNr + " from line #" + lineNr + ": ";
                                        // Storing properties of the frame
                                        provFrame['Parts'][fix] = new Object;
                                        provFrame['Parts'][fix]['Timestamp'] = fields.groups.Timestamp;
                                        result_log += "Timestamp='" + provFrame['Parts'][fix]['Timestamp'] + "' ";
                                        var localpayload = fields.groups.Data;
                                        provFrame['Parts'][fix]['Data'] = localpayload;
                                        result_log += "Data='" + provFrame['Parts'][fix]['Data'] + "' ";
                                        
                                        provFrame['Parts'][fix]['Payload'] = localpayload.replace(/ /g, "").substring(3);
                                        
                                        result_log += "Payload='" + provFrame['Parts'][fix]['Payload'] + "' ";
                                        provFrame['Parts'][fix]['Tail'] = fields.groups.Tail;
                                        result_log += "Tail='" + provFrame['Parts'][fix]['Tail'] + "'\\n";
                                        //console.log("Adding payload: " + provFrame['Parts'][fix]['Payload']);

                                        // Check if this is the last frame of the provisionning frames
                                        if (provFrame['Parts'][fix]['Payload'].startsWith("010055"))
                                        {
                                            // Frame cannot be longer than 64 bytes (by spec) or 128 chars
                                            if (payload !== undefined && payload.length > 128)
                                                payload = payload.substring(0, 128);
                                            //console.log("End of frame found for the final payload: " + payload);

                                            // Next we will not be searching for continuing prov frames
                                            // This frame is complete, Next let's search another one
                                            parsingFrame = false;
                                            frameNr++;
                                            // A frame just completed... switch back on finding a frame start
                                            var insertStmt = "INSERT INTO MACProvFrames (LogFileId, Frame) \
                                                                     VALUES             (        ?,     ?);";
                                            keystoredb.run(
                                                insertStmt,
                                                [logFileID, provFrame['Payload']],
                                                (err) =>
                                                {
                                                    if (err)
                                                        throw new Error();
                                                    provFrame = new Object;                                                
                                                }
                                            );
                                            break;
                                        }
                                        else {
                                            // Accumulate payload
                                            payload += provFrame['Parts'][fix]['Payload'];
                                            provFrame['Payload'] = payload;
                                        }
                                        result_log += "Frame #" + lineNr + " payload = '" + provFrame['Payload'] + "'\\n";
                                    }
                                }
                                while(0);
                                lineNr++;
                                s.resume();                    
                            }
                        }

                        // Prov Frame Processing end handler (onEnd event handler)
                        // Frames have been persisted in DB
                        // Now change 
                        function processProvFrames_OnEnd()
                        {
                            // Update database by setting ProvFramesExtracted flag to true
                            var updateStmt = "UPDATE LogFiles SET ProvFramesExtracted='1', LinesNb=?  WHERE id=?";
                            keystoredb.run(
                                updateStmt,
                                [lineNr, logFileID],
                                (err) =>
                                {
                                    if (err)
                                        throw new Error();
                                    
                                    renderParams['result_log'] = result_log;
                                    renderParams['status'] = "'Frames extracted from log file with id = " + renderParams['logFileID'] + "! Processing log is here after:'";
                                    response.render(
                                        'extract_mac_frames',
                                        renderParams
                                    );
                                }
                            )
                        }

                        /* ========================================================================================================================= */
                        /* GET /extract_mac_frames/:logFileId                                                                                        */
                        /* ========================================================================================================================= */
                        router.get(
                            '/extract_mac_frames/:logFileId',
                            (req, res, next) =>
                            {
                                console.log("*** GET /extract_mac_frames/:logFileId");
                                var activeKeys = new Object;
                                var k_mac_ecu = "Not Set !";
                                var k_master_ecu = "Not Set !";
                                keystoredb.get(
                                    "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                                    (err, key) =>
                                    {
                                        if (err)
                                        {
                                            console.trace("Error on statement: SELECT MacEcu, MasterEcu FROM ActiveKeys");
                                            next(err.status || 500);
                                            return;
                                        }
                                        if (key != undefined)
                                        {
                                            k_mac_ecu = key.MacEcu;
                                            k_master_ecu = key.MasterEcu;
                                        }
                                        activeKeys['kMacEcu'] = k_mac_ecu;
                                        activeKeys['kMasterEcu'] = k_master_ecu;

                                        // Select log file with id :logFileId with ProvFramesExtracted flag being false
                                        // Initialization of parameters for rendering the page
                                        logFileID = Number.parseInt(req.params['logFileId']);
                                        renderParams =
                                            {
                                                title: 'Extract MAC Prov frames',
                                                help: 'Extract MAC Prov frames from a selected log file in DB',
                                                logFileID: logFileID,
                                                status: "",
                                                activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                accordionTab: 1
                                            };
                                        var stmt = "SELECT id, Name, UUID FROM LogFiles WHERE id = ?";
                                        keystoredb.get(
                                            stmt,
                                            [logFileID],
                                            (err, row) =>
                                            {
                                                // Examples of logging entries in log files
                                                //
                                                //   19.232049 CANFD   1 Rx        7c3  DTOOL_to_ADAS_FD                 1 0 8  8 10 44 31 01 02 53 00 00   106156  135   303000 c80016cf 4ba00150 4b280150 20002776 2000091c
                                                // 8.191 1 7C3             Rx   d 8 02 10 03 00 00 00 00 00
                                                //   7.157965 CANFD   2 Rx        7c3  DTOOL_to_ADAS_FD                 1 0 8  8 02 3e 00 55 55 55 55 55   104657  132   323000 a800f7a3 4ba00150 4b280150 20002776 2000091c
                                                //   0.007142 CANFD   1 Rx        192  ADAS_A10C_FD                     1 0 8  8 00 00 50 04 7f ff 00 10   103656  136   303000 980150f4 4ba00150 4b280150 20002776 2000091c
                                                //   0.002801 CANFD   1 Rx        25e  ADASISv2_A101_FD                 1 0 8  8 00 00 00 00 00 00 00 00   105156  139   303000 f800b73d 4ba00150 4b280150 20002776 2000091c
                                                //   
                                                if (err)
                                                {
                                                    console.trace("Error on statement: " + stmt);
                                                    next(err.status || 500);
                                                    return;
                                                }

                                                console.log('==============================================================');
                                                console.log('File \'' + row.Name + '\' !');
                                                result_log += "==============================================================\\n";
                                                result_log += "File '" + row.Name + "' !\\n";

                                                var logFilePath = path.join(DbLogPath, row.Name);

                                                var provFrameRE  = /^ ? ?(?<Timestamp>[0-9.]*) (?<ProvRE>([A-Z]+)? *[12]? ?Rx *[0-9a-zA-Z]+  (?<Name>DTOOL_to_[A-Za-z0-9_]+)) +[0-9] [0-9] [a-zA-Z0-9] *(?<Data>[ 0-9a-zA-Z]+31 01 02 53[ 0-9a-zA-Z]+)   (?<Tail>(.*)(   .*))$/;
                                                var provFrame = new Object;
                                                var provFramesStart = new Array;
                                                var parsingFrame = false;
                                                response = res;
                                                
                                                s =
                                                    fs.createReadStream(logFilePath)
                                                    .pipe(
                                                        es.split()
                                                    )
                                                    .pipe(
                                                        es.mapSync(
                                                            processProvFrames_OnLine
                                                        )
                                                        .on(
                                                            'error',
                                                            // Cannot put the router in the closure, then put error handler here
                                                            (err) =>
                                                            {
                                                                // Prov Frame Processing error handler
                                                                console.trace('Error while reading file.', err);
                                                                next(err.status || 500);
                                                                return;
                                                            }
                                                        )
                                                        .on(
                                                            'end',
                                                            processProvFrames_OnEnd
                                                        )
                                                    );
                                            }
                                        );
                                    }
                                );
                            }
                        );

                        /* ========================================================================================================================= */
                        /* GET /extract_mac_frames                                                                                                   */
                        /* ========================================================================================================================= */
                        router.get(
                            '/extract_mac_frames',
                            (req, res, next) =>
                            {
                                console.log("*** GET /extract_mac_frames");
                                var activeKeys = new Object;
                                var k_mac_ecu = "Not Set !";
                                var k_master_ecu = "Not Set !";
                                keystoredb.get(
                                    "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                                    (err, key) =>
                                    {
                                        if (key != undefined)
                                        {
                                            k_mac_ecu = key.MacEcu;
                                            k_master_ecu = key.MasterEcu;
                                        }
                                        activeKeys['kMacEcu'] = k_mac_ecu;
                                        activeKeys['kMasterEcu'] = k_master_ecu;
                                        
                                        // Select all log files with ProvFramesExtracted flag being false
                                        var stmt = "SELECT id, Name, UUID FROM LogFiles WHERE ProvFramesExtracted='0'";
                                        keystoredb.all(
                                            stmt,
                                            [],
                                            (err, rows) =>
                                            {
                                                // Examples of logging entries in log file
                                                //
                                                //   19.232049 CANFD   1 Rx        7c3  DTOOL_to_ADAS_FD                 1 0 8  8 10 44 31 01 02 53 00 00   106156  135   303000 c80016cf 4ba00150 4b280150 20002776 2000091c
                                                // 8.191 1 7C3             Rx   d 8 02 10 03 00 00 00 00 00
                                                //   7.157965 CANFD   2 Rx        7c3  DTOOL_to_ADAS_FD                 1 0 8  8 02 3e 00 55 55 55 55 55   104657  132   323000 a800f7a3 4ba00150 4b280150 20002776 2000091c
                                                //   0.007142 CANFD   1 Rx        192  ADAS_A10C_FD                     1 0 8  8 00 00 50 04 7f ff 00 10   103656  136   303000 980150f4 4ba00150 4b280150 20002776 2000091c
                                                //   0.002801 CANFD   1 Rx        25e  ADASISv2_A101_FD                 1 0 8  8 00 00 00 00 00 00 00 00   105156  139   303000 f800b73d 4ba00150 4b280150 20002776 2000091c
                                                //   
                                                if (err)
                                                {
                                                    next(err.status || 500);
                                                    return;
                                                }
                                                // Initialization of parameters for rendering the page
                                                renderParams =
                                                    {
                                                        title: 'Extract MAC Prov frames',
                                                        help: 'Extract MAC Prov frames from a selected log file in DB',
                                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                        status: "",
                                                        result_log: "",
                                                        accordionTab: 1
                                                    };
                                                
                                                var framesNb = rows.length;
                                                // For each log file found
                                                rows.forEach(
                                                    (row) =>
                                                    {
                                                        result_log += "==============================================================\\n";
                                                        result_log += "File '" + row.Name + "!\\n";
                                                        var provFrameRE  = /^ ? ?(?<Timestamp>[0-9.]*) (?<ProvRE>([A-Z]+)? *[12]? ?Rx *[0-9a-zA-Z]+  (?<Name>DTOOL_to_[A-Za-z0-9_]+)) +[0-9] [0-9] [a-zA-Z0-9] *(?<Data>[ 0-9a-zA-Z]+31 01 02 53[ 0-9a-zA-Z]+)   (?<Tail>(.*)(   .*))$/;
                                                        var provFramesStart = new Array;
                                                        var provFrame;
                                                        var parsingFrame = false;
                                                        var logFileID = row.id;
                                                        var logFilePath = path.join(DbLogPath, row.Name);
                                                        logFileName = row.Name;
                                                        var lineNr = 0;
                                                        response = res;
                                                        
                                                        s = fs.createReadStream(logFilePath)
                                                            .pipe(es.split())
                                                            .pipe(
                                                                es.mapSync(
                                                                    processProvFrames_OnLine
                                                                )
                                                                .on(
                                                                    'error',
                                                                    // Cannot put the router in the closure, then put error handler here
                                                                    (err) =>
                                                                    {
                                                                        // Prov Frame Processing error handler
                                                                        console.trace('Error while reading file.', err);
                                                                        next(err.status || 500);
                                                                        return;
                                                                    }
                                                                )
                                                                .on(
                                                                    'end',
                                                                    processProvFrames_OnEnd
                                                                )
                                                            );
                                                    }
                                                );
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                )(this);
                
                /* ========================================================================================================================= */
                /* GET /list_mac_prov_frame/:logFileId                                                                                       */
                /* ========================================================================================================================= */
                router.get(
                    '/list_mac_prov_frame/:logFileId',
                    (req, res, next) =>
                    {
                        console.log("*** GET /list_mac_prov_frame/:logFileId");
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;

                                var logFileId = Number.parseInt(req.params['logFileId']);
                                var stmt = "SELECT DISTINCT f.id, l.Name, f.Frame, f.SHECmdExtracted \
                                            FROM LogFiles l \
                                            LEFT JOIN MACProvFrames f ON l.id = f.LogFileId \
                                            WHERE length(f.Frame) > 0 AND l.id = ?";
                                keystoredb.all(
                                    stmt,
                                    [logFileId],
                                    (err, rows) =>
                                    {
                                        if (err)
                                        {
                                            next(err.status || 500);
                                            return;
                                        }
                                        var renderParams =
                                            {
                                                title: 'List MAC Provisionning frames',
                                                help: 'List MAC provisionning frames extracted',
                                                activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                accordionTab: 1
                                            };
                                        var contentHtml = "";
                                        var ix = 0;
                                        rows.forEach(
                                            (row) =>
                                            {
                                                if (ix != 0)
                                                    contentHtml += ",";
                                                contentHtml +=
                                                    "{id:" + row.id + "," +
                                                    "name:'" + row.Name + "'," +
                                                    "frame:'" + row.Frame + "'," +
                                                    "sheCmdExtracted:" + (row.SHECmdExtracted ? "true" : "false") + "}";
                                                ix++;
                                            }
                                        );
                                        renderParams['macprovframes'] = "[" + contentHtml + "]";
                                        res.render(
                                            'list_mac_prov_frame',
                                            renderParams
                                        );                              
                                    }
                                );
                            }
                        );
                    }
                );
                
                /* ========================================================================================================================= */
                /* GET list_mac_prov_frame                                                                                                   */
                /* ========================================================================================================================= */
                router.get(
                    '/list_mac_prov_frame',
                    (req, res, next) =>
                    {
                        console.log("*** GET /list_mac_prov_frame");
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys ORDER BY id",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;

                                var stmt = "SELECT DISTINCT f.id, l.Name, f.Frame, f.SHECmdExtracted \
                                                    FROM LogFiles l \
                                                                  LEFT JOIN MACProvFrames f ON l.id = f.LogFileId \
                                                    WHERE length(f.Frame) > 0";
                                keystoredb.all(
                                    stmt,
                                    [],
                                    (err, rows) =>
                                    {
                                        if (err)
                                        {
                                            next(err.status || 500);
                                            return;
                                        }
                                        var renderParams =
                                            {
                                                title: 'List MAC Provisionning frames',
                                                help: 'List MAC provisionning frames extracted',
                                                activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                accordionTab: 1
                                            };

                                        var contentHtml = "";
                                        var ix = 0;
                                        rows.forEach(
                                            (row) =>
                                            {
                                                if (ix != 0)
                                                    contentHtml += ",";
                                                contentHtml +=
                                                    "{id:" + row.id + "," +
                                                    "name:'" + row.Name + "'," +
                                                    "frame:'" + row.Frame + "'," +
                                                    "sheCmdExtracted:" + (row.SHECmdExtracted ? "true" : "false") + "}";
                                                ix++;
                                            }
                                        );
                                        renderParams['macprovframes'] = "[" + contentHtml + "]";
                                        res.render(
                                            'list_mac_prov_frame',
                                            renderParams
                                        );                              
                                    }
                                );
                            }
                        );
                    }
                );

                /*
                 * ========================================================================================================================= *
                 *                                                                                                                           *
                 *                                             Processing Secured MAC frames                                                 *
                 *                                                                                                                           *
                 * ========================================================================================================================= *
                 */

                /* ========================================================================================================================= */
                /* GET /extract_secured_mac_frames/:logFileId.                                                                               */
                /* ========================================================================================================================= */
                router.get(
                    '/extract_secured_mac_frames/:logFileId',
                    (req, res, next) =>
                    {
                        console.log("*** GET /extract_secured_mac_frames/:logFileId");
                        var logFileId = Number.parseInt(req.params['logFileId']);
                        var result_log = "";
                        var oneline_result_log = "";
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;

                                var renderParams = 
                                    {
                                        title: 'Extract secured MAC frames',
                                        help: 'Extract secured MAC frames from a selected log file in DB',
                                        logFileID: logFileId,
                                        status: "",
                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                        accordionTab: 2
                                    };
                                var stmt = "SELECT id, Name, UUID FROM LogFiles WHERE id = ? AND SecuredFramesExtracted = 0";
                                keystoredb.get(
                                    stmt,
                                    [logFileId],
                                    (err, row) =>
                                    {
                                        if (err || row === undefined)
                                        {
                                            next(err);
                                            return;
                                        }

                                        // Update LogFiles table for avoiding several extract
                                        var updateStmt = "UPDATE LogFiles SET SecuredFramesExtracted='1' WHERE LogFiles.id=?";
                                        keystoredb.run(
                                            updateStmt,
                                            [logFileId]
                                        );

                                        oneline_result_log += "File '" + row.Name + "' !\\n";
                                        var frameRE = /^ *(?<Timestamp>[0-9.]*) CANFD +[0-9] Rx +(?<id>[0-9a-fA-F]+) +(?<name>[A-Z0-9_]+SC_FD|FVSyncFrame_[A-Z0-9_]+|FVReSyncFrame_[A-Z0-9_]+) +[0-9] [0-9] [a-fA-F0-9] (?<payload>([0-9a-fA-F]{2} )+)(?<tmac>([0-9a-fA-F]{2} ){8})  .*/m;
                                        var frames = new Array;
                                        var stmt = "INSERT INTO SecuredFrames (Name, TimeStamp, FrameId, EcuName, DLC, tMAC, FV, Payload, Msb, Lsb, Pad) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                                        var lineNr = 0;
                                        var filePath = path.join(DbLogPath, row.Name);
                                        var s =
                                            fs.createReadStream(filePath)
                                            .pipe(
                                                es.split()
                                            )
                                            .pipe(
                                                es.mapSync(
                                                    (line) =>
                                                    {
                                                        // pause the readstream
                                                        s.pause();
                                                        
                                                        var fields;
                                                        if ((fields = frameRE.exec(line)))
                                                        {
                                                            // Found a frame => parsing it
                                                            oneline_result_log += " - line #" + i + ": ";
                                                            // TimeStamp (ex.: 123.654352)
                                                            var tstamp = fields.groups.Timestamp;
                                                            // Frame ID (ex.: 6e3)
                                                            var fid = fields.groups.id;
                                                            // Frame Name
                                                            var name = fields.groups.name;
                                                            // Payload of the frame
                                                            var payload = fields.groups.payload;
                                                            // Height MSBytes of the last AES-cmac block (MAC authentication tag)
                                                            var tmac = fields.groups.tmac.trim().replace(/ /g, '');
                                                            // Log these to page log textarea
                                                            oneline_result_log += "   = tstamp = '" + tstamp + "'";
                                                            oneline_result_log += " id = '" + fid + "'";
                                                            oneline_result_log += " name = '" + name + "'";
                                                            oneline_result_log += " tmac = '" + tmac + "'";
                                                            // Processing payload for extracting FVs
                                                            //  - FVs from Sync frames is the full ARC (6 bytes)
                                                            //  - FVs from ReSync frames if a table of full Rx ARC for every ECU
                                                            //  - For SC_FD frames, no Full FV, only 2 bytes LSBytes
                                                            var resyncRE = /^FVReSyncFrame_(?<ecu>[A-Za-z0-9]+)_.*$/;
                                                            var syncRE = /^FVSyncFrame_(?<ecu>[A-Za-z0-9]+)_.*$/;
                                                            var scfdRE = /^(?<ecu>[A-Za-z0-9]+)_.*/;
                                                            var fv = "";
                                                            var pad = "";
                                                            var dlc = "";
                                                            var msb = "";
                                                            var lsb = "";
                                                            var ecuName = "";
                                                            var ecuFields;
                                                            // Sync frame
                                                            if ((ecuFields = syncRE.exec(name)) != null)
                                                            {
                                                                // Extracting padding from payload
                                                                var padRE = /(?<pad>00 ?){0,15}$/;
                                                                if ((fields = padRE.exec(payload)) != null)
                                                                {
                                                                    pad = payload.substring(fields.index).trim().replace(/ /g, '');
                                                                    payload = payload.substring(0, fields.index).trim();
                                                                }
                                                                var fvRE = /^(?<dlc>[0-9a-fA-F]{2}) (?<fv>([0-9a-fA-F]{2} ?){6})$/;
                                                                ecuName = ecuFields.groups.ecu;
                                                                if ((fields = fvRE.exec(payload)) != null)
                                                                {
                                                                    dlc = fields.groups.dlc;
                                                                    fv = fields.groups.fv.replace(/ /g, '');
                                                                    msb = fv.substring(0, 8).replace(/ /g, '');
                                                                    lsb = fv.substring(8).replace(/ /g, '');
                                                                    payload = '';
                                                                }
                                                                else
                                                                    throw 'RegEx error for getting FV from Sync frame !';
                                                            }
                                                            // ReSync frame
                                                            else if ((ecuFields = resyncRE.exec(name)) != null)
                                                            {
                                                                // Extracting padding from payload
                                                                var padRE = /(?<pad>00 ?){0,15}$/;
                                                                if ((fields = padRE.exec(payload)) != null)
                                                                {
                                                                    pad = payload.substring(fields.index).trim().replace(/ /g, '');
                                                                    payload = payload.substring(0, fields.index).trim();
                                                                }
                                                                ecuName = ecuFields.groups.ecu;
                                                                var fvRE = /^(?<dlc>[0-9a-fA-F]{2}) (?<fvstbl>(([0-9a-fA-F]{2} ?){6}){6})$/;
                                                                var fvRE = /^(?<dlc>[0-9a-fA-F]{2}) (?<fvstbl>(((?<fv>[0-9a-fA-F]{2}) ?){6}){6})$/;
                                                                if ((fields = fvRE.exec(payload)) != null)
                                                                {
                                                                    dlc = fields.groups.dlc;
                                                                    fv = fields.groups.fvstbl.replace(/ /g, '');
                                                                    payload = '';
                                                                }
                                                                else
                                                                    throw 'RegEx error for getting FVs from ReSync frame !';
                                                            }
                                                            // SC_FD frame
                                                            else if ((ecuFields = scfdRE.exec(name)) != null)
                                                            {
                                                                // Extracting lsb from payload
                                                                var lsbRE = /(?<lsb>([a-fA-F0-9]{2}) ?){2}$/;
                                                                if ((fields = lsbRE.exec(payload)) != null)
                                                                {
                                                                    lsb = payload.substring(fields.index).replace(/ /g, '').trim();
                                                                    payload = payload.substring(0, fields.index).trim();
                                                                }
                                                                // Extracting padding from payload
                                                                var padRE = /(?<pad>00 ?){0,15}$/;
                                                                if ((fields = padRE.exec(payload)) != null)
                                                                {
                                                                    pad = payload.substring(fields.index).trim().replace(/ /g, '');
                                                                    payload = payload.substring(0, fields.index).trim();
                                                                }
                                                                ecuName = ecuFields.groups.ecu;
                                                                var scfdRE = /^(?<dlc>[0-9a-fA-F]{2}) (?<payload>([0-9a-fA-F]{2} ?)+)$/;
                                                                if ((fields = scfdRE.exec(payload)) != null)
                                                                {
                                                                    dlc = fields.groups.dlc;
                                                                    payload = fields.groups.payload.replace(/ /g, '');
                                                                }
                                                                else
                                                                    throw 'RegEx error for getting payload from SC_FD frame !';
                                                            }
                                                            oneline_result_log += " dlc = '" + dlc + "'";
                                                            oneline_result_log += " payload = '" + payload + "'";
                                                            oneline_result_log += " fv = '" + fv + "'";
                                                            oneline_result_log += " lsb = '" + lsb + "'";
                                                            oneline_result_log += " msb = '" + msb + "'";
                                                            oneline_result_log += " pad = '" + pad + "'";
                                                            oneline_result_log += " ECUname = '" + ecuName + "'";
                                                            oneline_result_log += "\\n";
                                                            result_log += oneline_result_log,
                                                            oneline_result_log = "";                                                
                                                            keystoredb.run(
                                                                stmt,
                                                                [name, tstamp, fid, ecuName, dlc, tmac, fv, payload, msb, lsb, pad]
                                                            );
                                                        }

                                                        // resume the readstream, possibly from a callback
                                                        s.resume();
                                                    }
                                                ).on(
                                                    'error',
                                                    (err) =>
                                                    {
                                                        console.log("Error while processing '" + filePath + "' !");
                                                        next(err.status || 500);
                                                        return;
                                                    }
                                                ).on(
                                                    'end',
                                                    () =>
                                                    {
                                                        console.log("End of initial processing for file '"+ newTargetFilePath +"'");
                                                        
                                                        renderParams['result_log'] = result_log;
                                                        renderParams['status'] =
                                                            " Secured frames extracted from log file with id = " + logFileId +
                                                            "! Processing log is here after:";
                                                        res.render(
                                                            'extract_secured_mac_frames',
                                                            renderParams
                                                        );
                                                    }
                                                )
                                            )
                                    }
                                );
                            }
                        );
                    }
                );

                /* ========================================================================================================================= */
                /* GET /extract_secured_mac_frames.                                                                                          */
                /* ========================================================================================================================= */
                router.get(
                    '/extract_secured_mac_frames',
                    (req, res, next) =>
                    {
                        console.log("*** GET /extract_secured_mac_frames");
                        var result_log = "";
                        var oneline_result_log = "";
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;

                                var renderParams = 
                                    {
                                        title: 'Extract secured MAC frames',
                                        help: 'Extract secured MAC frames from a selected log file in DB',
                                        status: "",
                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                        accordionTab: 2
                                    };
                                var stmt = "SELECT id, Name, UUID FROM LogFiles WHERE SecuredFramesExtracted = 0";
                                keystoredb.all(
                                    stmt,
                                    [],
                                    (err, rows) =>
                                    {
                                        if (rows.length == 0)
                                        {
                                            next('No log file found !');
                                            return;
                                        }

                                        rows.forEach(
                                            (row, rowix) => 
                                            {
                                                // Update LogFiles table for avoiding several extract
                                                var updateStmt = "UPDATE LogFiles SET SecuredFramesExtracted='1' WHERE LogFiles.id=?";
                                                keystoredb.run(
                                                    updateStmt,
                                                    [row.id]
                                                );

                                                oneline_result_log += "File '" + row.Name + "' !\\n";
                                                var frameRE = /^ *(?<Timestamp>[0-9.]*) CANFD +[0-9] Rx +(?<id>[0-9a-fA-F]+) +(?<name>[A-Z0-9_]+SC_FD|FVSyncFrame_[A-Z0-9_]+|FVReSyncFrame_[A-Z0-9_]+) +[0-9] [0-9] [a-fA-F0-9] (?<payload>([0-9a-fA-F]{2} )+)(?<tmac>([0-9a-fA-F]{2} ){8})  .*/m;
                                                var frames = new Array;
                                                var stmt = "INSERT INTO SecuredFrames (Name, TimeStamp, FrameId, EcuName, DLC, tMAC, FV, Payload, Msb, Lsb, Pad) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

                                                var lineNr = 0;
                                                var filePath = path.join(DbLogPath, row.Name);

                                                var s =
                                                    fs.createReadStream(filePath)
                                                    .pipe(
                                                        es.split()
                                                    )
                                                    .pipe(
                                                        es.mapSync(
                                                            (line) =>
                                                            {
                                                                // pause the readstream
                                                                s.pause();
                                                                
                                                                var fields;
                                                                if ((fields = frameRE.exec(lines[i])))
                                                                {
                                                                    // Found a frame => parsing it
                                                                    oneline_result_log += " - line #" + i + ": ";
                                                                    // TimeStamp (ex.: 123.654352)
                                                                    var tstamp = fields.groups.Timestamp;
                                                                    // Frame ID (ex.: 6e3)
                                                                    var fid = fields.groups.id;
                                                                    // Frame Name
                                                                    var name = fields.groups.name;
                                                                    // Payload of the frame
                                                                    var payload = fields.groups.payload;
                                                                    // Height MSBytes of the last AES-cmac block (MAC authentication tag)
                                                                    var tmac = fields.groups.tmac.trim().replace(/ /g, '');
                                                                    // Log these to page log textarea
                                                                    oneline_result_log += "   = tstamp = '" + tstamp + "'";
                                                                    oneline_result_log += " id = '" + fid + "'";
                                                                    oneline_result_log += " name = '" + name + "'";
                                                                    oneline_result_log += " tmac = '" + tmac + "'";
                                                                    // Processing payload for extracting FVs
                                                                    //  - FVs from Sync frames is the full ARC (6 bytes)
                                                                    //  - FVs from ReSync frames if a table of full Rx ARC for every ECU
                                                                    //  - For SC_FD frames, no Full FV, only 2 bytes LSBytes
                                                                    var resyncRE = /^FVReSyncFrame_(?<ecu>[A-Za-z0-9]+)_.*$/;
                                                                    var syncRE = /^FVSyncFrame_(?<ecu>[A-Za-z0-9]+)_.*$/;
                                                                    var scfdRE = /^(?<ecu>[A-Za-z0-9]+)_.*/;
                                                                    var fv = "";
                                                                    var pad = "";
                                                                    var dlc = "";
                                                                    var msb = "";
                                                                    var lsb = "";
                                                                    var ecuName = "";
                                                                    var ecuFields;
                                                                    // Sync frame
                                                                    if ((ecuFields = syncRE.exec(name)) != null)
                                                                    {
                                                                        // Extracting padding from payload
                                                                        var padRE = /(?<pad>00 ?){0,15}$/;
                                                                        if ((fields = padRE.exec(payload)) != null)
                                                                        {
                                                                            pad = payload.substring(fields.index).trim().replace(/ /g, '');
                                                                            payload = payload.substring(0, fields.index).trim();
                                                                        }
                                                                        ecuName = ecuFields.groups.ecu;
                                                                        var fvRE = /^(?<dlc>[0-9a-fA-F]{2}) (?<fv>([0-9a-fA-F]{2} ?){6})$/;
                                                                        if ((fields = fvRE.exec(payload)) != null)
                                                                        {
                                                                            dlc = fields.groups.dlc;
                                                                            fv = fields.groups.fv.replace(/ /g, '');
                                                                            msb = fv.substring(0, 8).replace(/ /g, '');
                                                                            lsb = fv.substring(8).replace(/ /g, '');
                                                                            payload = '';
                                                                        }
                                                                        else
                                                                            throw 'RegEx error for getting FV from Sync frame !';
                                                                    }
                                                                    // ReSync frame
                                                                    else if ((ecuFields = resyncRE.exec(name)) != null)
                                                                    {
                                                                        // Extracting padding from payload
                                                                        var padRE = /(?<pad>00 ?){0,15}$/;
                                                                        if ((fields = padRE.exec(payload)) != null)
                                                                        {
                                                                            pad = payload.substring(fields.index).trim().replace(/ /g, '');
                                                                            payload = payload.substring(0, fields.index).trim();
                                                                        }
                                                                        ecuName = ecuFields.groups.ecu;
                                                                        var fvRE = /^(?<dlc>[0-9a-fA-F]{2}) (?<fvstbl>(((?<fv>[0-9a-fA-F]{2}) ?){6}){6})$/;
                                                                        if ((fields = fvRE.exec(payload)) != null)
                                                                        {
                                                                            dlc = fields.groups.dlc;
                                                                            fv = fields.groups.fvstbl.replace(/ /g, '');
                                                                            payload = '';
                                                                        }
                                                                        else
                                                                            throw 'RegEx error for getting FVs from ReSync frame !';
                                                                    }
                                                                    // SC_FD frame
                                                                    else if ((ecuFields = scfdRE.exec(name)) != null)
                                                                    {
                                                                        // Extracting lsb from payload
                                                                        var lsbRE = /(?<lsb>([a-fA-F0-9]{2}) ?){2}$/;
                                                                        if ((fields = lsbRE.exec(payload)) != null)
                                                                        {
                                                                            lsb = payload.substring(fields.index).replace(/ /g, '').trim();
                                                                            payload = payload.substring(0, fields.index).trim();
                                                                        }
                                                                        // Extracting padding from payload
                                                                        var padRE = /(?<pad>00 ?){0,15}$/;
                                                                        if ((fields = padRE.exec(payload)) != null)
                                                                        {
                                                                            pad = payload.substring(fields.index).trim().replace(/ /g, '');
                                                                            payload = payload.substring(0, fields.index).trim();
                                                                        }
                                                                        ecuName = ecuFields.groups.ecu;
                                                                        var scfdRE = /^(?<dlc>[0-9a-fA-F]{2}) (?<payload>([0-9a-fA-F]{2} ?)+)$/;
                                                                        if ((fields = scfdRE.exec(payload)) != null)
                                                                        {
                                                                            dlc = fields.groups.dlc;
                                                                            payload = fields.groups.payload.replace(/ /g, '');
                                                                        }
                                                                        else
                                                                            throw 'RegEx error for getting payload from SC_FD frame !';
                                                                    }
                                                                    oneline_result_log += " payload = '" + payload + "'";
                                                                    oneline_result_log += " fv = '" + fv + "'";
                                                                    oneline_result_log += " lsb = '" + lsb + "'";
                                                                    oneline_result_log += " msb = '" + msb + "'";
                                                                    oneline_result_log += " pad = '" + pad + "'";
                                                                    oneline_result_log += " ECUname = '" + ecuName + "'";
                                                                    oneline_result_log += "\\n";
                                                                    result_log += oneline_result_log;
                                                                    oneline_result_log = "";
                                                                    keystoredb.run(
                                                                        stmt,
                                                                        [name, tstamp, fid, ecuName, dlc, tmac, fv, payload, msb, lsb, pad]
                                                                    );
                                                                    
                                                                    // resume the readstream, possibly from a callback
                                                                    s.resume();
                                                                }
                                                            }
                                                        ).on(
                                                            'error',
                                                            (err) =>
                                                            {
                                                                console.log("Error while processing '" + newTargetFilePath + "' !");
                                                                next(err.status || 500);
                                                                return;
                                                            }
                                                        ).on(
                                                            'end',
                                                            () =>
                                                            {
                                                                console.log("End of initial processing for file '"+ newTargetFilePath +"'");
                                                                
                                                                renderParams['result_log'] = result_log;
                                                                renderParams['status'] =
                                                                    " Secured frames extracted from log file with id = " + logFileId +
                                                                    "! Processing log is here after:";
                                                                res.render(
                                                                    'extract_mac_frames',
                                                                    renderParams
                                                                );
                                                                
                                                            }
                                                        )
                                                    )
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
                
                /* ========================================================================================================================= */
                /* GET /compute_secured_frames_mac_by_id                                                                                     */
                /* ========================================================================================================================= */
                router.get(
                    '/compute_secured_frames_mac_by_id',
                    (req, res, next) =>
                    {
                        console.log("*** GET /compute_secured_frames_mac_by_id");
                        var result_log = "";
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;

                                var renderParams = 
                                    {
                                        title: 'Compute secured frames MAC',
                                        help: 'Compute MAC for secured frames in DB',
                                        status: "",
                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                        accordionTab: 2
                                    };
                                var stmt = "SELECT * FROM SecuredFrames WHERE Mac = 'unknown'";
                                keystoredb.all(
                                    stmt,
                                    [],
                                    (err, rows) =>
                                    {
                                        if (err)
                                        {
                                            next(err);
                                            return;
                                        }
                                        renderParams['status'] =
                                            " Secured frames extracted Processing log is here after:";
                                        res.render(
                                            'compute_secured_frames_mac_by_id',
                                            renderParams
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
                        
                /* ========================================================================================================================= */
                /* GET /compute_secured_mac_frames/:frameId                                                                                  */
                /* ========================================================================================================================= */
                router.get(
                    '/compute_secured_frames_mac/:frameId',
                    (req, res, next) =>
                    {
                        console.log("*** GET /compute_secured_frames_mac/:frameId");
                        var frameId = Number.parseInt(req.params['frameId']);
                        var result_log = "";
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        var renderParams;
                        
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;

                                renderParams = 
                                    {
                                        title: 'Compute secured frames MAC',
                                        help: 'Compute MAC for secured frames in DB',
                                        status: "",
                                        result_log: "",
                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                        accordionTab: 2
                                    };
                                var stmt = "SELECT * FROM SecuredFrames WHERE id = ? ORDER BY TimeStamp ASC";
                                keystoredb.get(
                                    stmt,
                                    [frameId],
                                    (err, row) =>
                                    {
                                        if (err)
                                        {
                                            next(err);
                                            return;
                                        }

                                        var scfdRegex = /^.*SC_FD.*$/;
                                        if (scfdRegex.test(row.Name))
                                        {
                                            var ecuRegex = /^(?<ecuName>[A-Za-z0-9]+)_.*$/;
                                            fields = ecuRegex.exec(row.Name);
                                            var ecuName = fields.groups.ecuName;
                                            var stmtDomain =
                                                "SELECT DISTINCT ecu.id, ecu.Name, ecu.isDomainMaster, ecu.DomainMasterId, domain.Name as DomainName " +
                                                "FROM ECUs as ecu "+
                                                "INNER JOIN ECUs as domain ON ecu.DomainMasterId = domain.id "+
                                                "WHERE ecu.Name = ?";
                                            keystoredb.get(
                                                stmtDomain,
                                                [ecuName],
                                                (err, ecuRow) =>
                                                {
                                                    if (err)
                                                    {
                                                        next(err);
                                                        return;
                                                    }
                                                    console.log("domain master ecu = " + ecuRow.DomainName);
                                                    var syncFrameCntStmt = "SELECT COUNT(id) AS row_count FROM SecuredFrames WHERE Name LIKE ? AND TimeStamp < ? ORDER BY TimeStamp DESC";
                                                    keystoredb.get(
                                                        syncFrameCntStmt,
                                                        ['FVSyncFrame_'+ecuRow.DomainName+'%', ecuRow.TimeStamp],
                                                        (err, cntRow) =>
                                                        {
                                                            if (err)
                                                            {
                                                                next(err);
                                                                return;
                                                            }
                                                            if (cntRow.row_count == 0)
                                                            {
                                                                var updStmt = "UPDATE SecuredFrames SET Mac = ? WHERE id = ?";
                                                                keystoredb.run(
                                                                    updStmt,
                                                                    ['Undecided', row.id]
                                                                );                                                                        
                                                            }
                                                            else
                                                            {
                                                                var syncFrameStmt = "SELECT * FROM SecuredFrames WHERE Name LIKE ? AND TimeStamp < ? ORDER BY TimeStamp DESC LIMIT 1";
                                                                keystoredb.run(
                                                                    syncFrameStmt,
                                                                    ['FVSyncFrame_'+ecuRow.DomainName+'%', ecuRow.TimeStamp],
                                                                    (err, syncRow) =>
                                                                    {
                                                                        console.log("Domain master Sync frame MSB = " + syncRow.FV);
                                                                        var bufferKey = Buffer.from(activeKeys['kMacEcu']);
                                                                        var encshe = new encSHE(
                                                                            row.FrameId,
                                                                            row.Name,
                                                                            row.TimeStamp,
                                                                            row.ecuName,
                                                                            row.DLC,
                                                                            Buffer.from(row.tMAC, 'hex'),
                                                                            Buffer.from(syncRow.FV, 'hex'),
                                                                            Buffer.from(row.Payload, 'hex'),
                                                                            Buffer.from(syncRow.Msb, 'hex'),
                                                                            Buffer.from(row.Lsb, 'hex'),
                                                                            Buffer.from(row.Pad, 'hex')
                                                                        );
                                                                        var updStmt = "UPDATE SecuredFrames SET Mac = ? WHERE id = ?";
                                                                        keystoredb.run(
                                                                            updStmt,
                                                                            [(encshe.verifyMac(bufferKey, row.tMAC) ? 'Valid' : 'KO'), row.id]
                                                                        );
                                                                    }
                                                                );                                                                        
                                                            }
                                                        }
                                                    );                                                            
                                                }
                                            );
                                            
                                        }
                                        else
                                        {
                                            var bufferKey = Buffer.from(activeKeys['kMacEcu']);
                                            console.log(
                                                "id:" +row.FrameId +
                                                    " name:" +row.Name+
                                                    " time:" +row.TimeStamp+
                                                    " ecu:" +row.EcuName+
                                                    " dlc:" +row.DLC+
                                                    " tmac:" +row.tMAC+
                                                    " fv:" +row.FV+
                                                    " payload:" +row.Payload+
                                                    " msb:" +row.Msb+
                                                    " lsb:" +row.Lsb+
                                                    " pad:" +row.Pad
                                            );
                                            var encshe = new encSHE(
                                                row.FrameId,
                                                row.Name,
                                                row.TimeStamp,
                                                row.EcuName,
                                                row.DLC,
                                                Buffer.from(row.tMAC, 'hex'),
                                                Buffer.from(row.FV, 'hex'),
                                                Buffer.from(row.Payload, 'hex'),
                                                Buffer.from(row.Msb, 'hex'),
                                                Buffer.from(row.Lsb, 'hex'),
                                                Buffer.from(row.Pad, 'hex')
                                            );
                                            var updStmt = "UPDATE SecuredFrames SET Mac = ? WHERE id = ?";
                                            var macValid = (encshe.verifyMac(bufferKey, row.tMAC) ? 'Valid' : 'KO');
                                            
                                            keystoredb.run(
                                                updStmt,
                                                [macValid, row.id]
                                            );
                                        }
                                    }
                                );
                                
                            }
                        );
                        renderParams['result_log'] = result_log;
                        renderParams['status'] = " Secured frames extracted from log files! Processing log is here after:";
                        res.render(
                            'extract_mac_frames',
                            renderParams
                        );
                    }
                );

                /* ========================================================================================================================= */
                /* GET /compute_secured_mac_frames.                                                                                          */
                /* ========================================================================================================================= */
                router.get(
                    '/compute_secured_frames_mac',
                    (req, res, next) =>
                    {
                        console.log("*** GET /compute_secured_frames_mac");
                        var result_log = "";
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        var renderParams;
                        
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;

                                renderParams = 
                                    {
                                        title: 'Compute secured frames MAC',
                                        help: 'Compute MAC for secured frames in DB',
                                        status: "",
                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                        accordionTab: 2
                                    };
                                var stmt = "SELECT * FROM SecuredFrames WHERE Mac = '?' ORDER BY TimeStamp ASC";
                                keystoredb.all(
                                    stmt,
                                    [],
                                    (err, rows) =>
                                    {
                                        if (err)
                                        {
                                            next(err);
                                            return;
                                        }
                                        rows.forEach(
                                            (row) =>
                                            {
                                                var scfdRegex = /^.*SC_FD.*$/;
                                                if (scfdRegex.test(row.Name))
                                                {
                                                    var ecuRegex = /^(?<ecuName>[A-Za-z0-9]+)_.*$/;
                                                    fields = ecuRegex.exec(row.Name);
                                                    var ecuName = fields.groups.ecuName;
                                                    var stmtDomain =
                                                        "SELECT DISTINCT ecu.id, ecu.Name, ecu.isDomainMaster, ecu.DomainMasterId, domain.Name as DomainName " +
                                                        "FROM ECUs as ecu "+
                                                        "INNER JOIN ECUs as domain ON ecu.DomainMasterId = domain.id "+
                                                        "WHERE ecu.Name = ?";
                                                    keystoredb.get(
                                                        stmtDomain,
                                                        [ecuName],
                                                        (err, ecuRow) =>
                                                        {
                                                            if (err)
                                                            {
                                                                next(err);
                                                                return;
                                                            }
                                                            console.log("domain master ecu = " + ecuRow.DomainName);
                                                            var syncFrameCntStmt = "SELECT COUNT(id) AS row_count FROM SecuredFrames WHERE Name LIKE ? AND TimeStamp < ? ORDER BY TimeStamp DESC";
                                                            keystoredb.get(
                                                                syncFrameCntStmt,
                                                                ['FVSyncFrame_'+ecuRow.DomainName+'%', ecuRow.TimeStamp],
                                                                (err, cntRow) =>
                                                                {
                                                                    if (err)
                                                                    {
                                                                        next(err);
                                                                        return;
                                                                    }
                                                                    if (cntRow.row_count == 0)
                                                                    {
                                                                        var updStmt = "UPDATE SecuredFrames SET Mac = ? WHERE id = ?";
                                                                        keystoredb.run(
                                                                            updStmt,
                                                                            ['Undecided', row.id]
                                                                        );                                                                        
                                                                    }
                                                                    else
                                                                    {
                                                                        var syncFrameStmt = "SELECT * FROM SecuredFrames WHERE Name LIKE ? AND TimeStamp < ? ORDER BY TimeStamp DESC LIMIT 1";
                                                                        keystoredb.run(
                                                                            syncFrameStmt,
                                                                            ['FVSyncFrame_'+ecuRow.DomainName+'%', ecuRow.TimeStamp],
                                                                            (err, syncRow) =>
                                                                            {
                                                                                console.log("Domain master Sync frame MSB = " + syncRow.FV);
                                                                                var bufferKey = Buffer.from(activeKeys['kMacEcu']);
                                                                                var encshe = new encSHE(
                                                                                    row.FrameId,
                                                                                    row.Name,
                                                                                    row.TimeStamp,
                                                                                    row.ecuName,
                                                                                    row.DLC,
                                                                                    Buffer.from(row.tMAC, 'hex'),
                                                                                    Buffer.from(syncRow.FV, 'hex'),
                                                                                    Buffer.from(row.Payload, 'hex'),
                                                                                    Buffer.from(syncRow.Msb, 'hex'),
                                                                                    Buffer.from(row.Lsb, 'hex'),
                                                                                    Buffer.from(row.Pad, 'hex')
                                                                                );
                                                                                var updStmt = "UPDATE SecuredFrames SET Mac = ? WHERE id = ?";
                                                                                keystoredb.run(
                                                                                    updStmt,
                                                                                    [(encshe.verifyMac(bufferKey, row.tMAC) ? 'Valid' : 'KO'), row.id]
                                                                                );
                                                                            }
                                                                        );                                                                        
                                                                    }
                                                                }
                                                            );                                                            
                                                        }
                                                    );
                                                    
                                                }
                                                else
                                                {
                                                    var bufferKey = Buffer.from(activeKeys['kMacEcu']);
                                                    console.log(
                                                        "id:" +row.FrameId +
                                                            " name:" +row.Name+
                                                            " time:" +row.TimeStamp+
                                                            " ecu:" +row.EcuName+
                                                            " dlc:" +row.DLC+
                                                            " tmac:" +row.tMAC+
                                                            " fv:" +row.FV+
                                                            " payload:" +row.Payload+
                                                            " msb:" +row.Msb+
                                                            " lsb:" +row.Lsb+
                                                            " pad:" +row.Pad
                                                    );
                                                    var encshe = new encSHE(
                                                        row.FrameId,
                                                        row.Name,
                                                        row.TimeStamp,
                                                        row.EcuName,
                                                        row.DLC,
                                                        Buffer.from(row.tMAC, 'hex'),
                                                        Buffer.from(row.FV, 'hex'),
                                                        Buffer.from(row.Payload, 'hex'),
                                                        Buffer.from(row.Msb, 'hex'),
                                                        Buffer.from(row.Lsb, 'hex'),
                                                        Buffer.from(row.Pad, 'hex')
                                                    );
                                                    var updStmt = "UPDATE SecuredFrames SET Mac = ? WHERE id = ?";
                                                    var macValid = (encshe.verifyMac(bufferKey, row.tMAC) ? 'Valid' : 'KO');
                                                    
                                                    keystoredb.run(
                                                        updStmt,
                                                        [macValid, row.id]
                                                    );
                                                }
                                            }
                                        );
                                        
                                    }
                                );
                                renderParams['result_log'] = result_log;
                                renderParams['status'] = " Secured frames extracted from log files! Processing log is here after:";
                                res.render(
                                    'extract_mac_frames',
                                    renderParams
                                );
                            }
                        );
                    }
                );

                /* ========================================================================================================================= */
                /* GET /list_secured_frames/:page                                                                                                  */
                /* ========================================================================================================================= */
                router.get(
                    '/list_secured_frames/:page',
                    (req, res, next) =>
                    {
                        var result_log = "";
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        var page = (req.params['page'] !== undefined ? Number.parseInt(req.params['page']) : 1);
                        var renderParams;

                        console.log("*** GET /list_secured_frames/:page (= "+page+")");
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;

                                renderParams = 
                                    {
                                        title: 'List of secured frames',
                                        help: 'List secured frames stored in DB',
                                        status: "",
                                        content: "",
                                        curPage: 0,
                                        prevPage: 0,
                                        nextPage: 0,
                                        lastPage: 0,
                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                        accordionTab: 2
                                    };
                                countScfdStmt = "SELECT COUNT(id) AS row_count FROM SecuredFrames";
                                keystoredb.get(
                                    countScfdStmt,
                                    [],
                                    (err, countRow) =>
                                    {
                                        var number_of_pages = Math.floor(countRow.row_count / 20);
                                        if (number_of_pages < (countRow.row_count / 20))
                                            number_of_pages++;
                                        var cur_page = page;
                                        var cur_page_less_1 = (cur_page > 1 ? cur_page-1 : 1);
                                        var cur_page_plus_1 = ((cur_page+1) < number_of_pages ? (cur_page+1) : number_of_pages);
                                        renderParams['lastPage'] = number_of_pages;
                                        renderParams['curPage'] = cur_page;
                                        renderParams['prevPage'] = cur_page_less_1;
                                        renderParams['nextPage'] = cur_page_plus_1;
                                        
                                        scfdStmt = "SELECT * FROM SecuredFrames LIMIT 20 OFFSET ?";
                                        keystoredb.all(
                                            scfdStmt,
                                            [(cur_page -1) * 20 > 0 ? ((cur_page -1) * 20) : 0],
                                            (err, rows) =>
                                            {
                                                if (err)
                                                {
                                                    next(err);
                                                    return;
                                                }
                                                var content = "[";
                                                rows.forEach(
                                                    (row, ix) =>
                                                    {
                                                        if (ix > 0 && ix < 20)
                                                            content += ",";
                                                        with (row)
                                                        {
                                                            content += "{";
                                                            content += "id:" + id + ",";
                                                            content += "Name:'" + Name + "',";
                                                            content += "TimeStamp:" + TimeStamp + ",";                                                            
                                                            content += "FrameType:'" + FrameId + "',";                                                            
                                                            content += "EcuName:'" + EcuName + "',";                                                            
                                                            content += "tMAC:'0x" + tMAC + "',";                                                            
                                                            content += "DLC:'0x" + DLC + "',";                                                            
                                                            content += "Payload:'" + (Payload.length ? "0x" : "") + Payload + "',";                                                            
                                                            content += "FV:'" + (FV.length ? "0x" : "") + FV + "',";                                                            
                                                            content += "Msb:'" + (Msb.length ? "0x" : "") + Msb + "',";                                                            
                                                            content += "Lsb:'" + (Lsb.length ? "0x" : "") + Lsb + "',";                                                            
                                                            content += "Pad:'" + (Pad.length ? "0x" : "") + Pad + "',";                                                            
                                                            content += "Mac:'" + Mac + "',";                                                            
                                                            content += "SyncFrameId:'" + SyncFrameId + "'";
                                                            content += "}";
                                                        }
                                                    }
                                                );
                                                content += "]";
                                                renderParams['scfdFrames'] = content;
                                                res.render(
                                                    "list_secured_frames",
                                                    renderParams
                                                );
                                            }
                                        );
                                    }
                                );
                                
                            }
                        );
                    }
                );

                /*
                 * ========================================================================================================================= *
                 *                                                                                                                           *
                 *                                                  Processing of SHE cmd args                                               *
                 *                                                                                                                           *
                 * ========================================================================================================================= *
                 */

                /* ========================================================================================================================= */
                /* GET /list_she_args_packets/:frameId                                                                                       */
                /* ========================================================================================================================= */
                router.get(
                    '/extract_she_args_packets/:frameId',
                    (req, res, next) =>
                    {
                        var frameId = Number.parseInt(req.params['frameId']);
                        console.log("*** GET /extract_she_args_packets/:frameId");
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;

                                // Cut Prov frame in 2 64 bytes packets: MSB -> M1, LSB -> M2
                                var bufM2;
                                var stmt = "SELECT Frame FROM MACProvFrames WHERE id = ?";
                                keystoredb.get(
                                    stmt,
                                    [frameId],
                                    (err, row) =>
                                    {
                                        var SHE_m2 = row.Frame.substring(32, 64);
                                        var bufferM2 = Buffer.from(SHE_m2);
                                        var bufferKMasterEcu = Buffer.from(activeKeys['kMasterEcu']);

                                        var bufM2 = she.decrypt_M2(bufferM2, bufferKMasterEcu);
                                        var cid = "0x" + she.getCID(bufM2);
                                        var fid = "0x" + she.getFID(bufM2);
                                        var macKey = "0x" + she.getKEY(bufM2).toString('hex');
                                        
                                        contentHtml += "[{m2:'" + bufM2.toString('hex') + "',";
                                        contentHtml += "cid:'" + cid + "',";
                                        contentHtml += "fid:'" + fid + "',";
                                        contentHtml += "key:'" + macKey + "'}]";
                                        
                                        // Create records in DB and mark the frame SHE cmd args as extracted
                                        keystoredb.serialize(
                                            () =>
                                            {
                                                keystoredb.run(
                                                    "UPDATE MACProvFrames SET SHECmdExtracted = 1 WHERE id = ?",
                                                    [req.params['frameId']]
                                                );
                                                keystoredb.run(
                                                    "INSERT INTO SHEArgsPackets (MACProvFrameId, M2) VALUES (?, ?, ?)",
                                                    [req.params['frameId'], bufM2]
                                                );
                                                keystoredb.run(
                                                    "INSERT INTO MACKeys (MACProvFrameId, MacKey, cid, fid) VALUES (?, ?, ?)",
                                                    [req.params['frameId'], macKey, cid, fid]
                                                );
                                            }
                                        );
                                        res.render(
                                            'extract_she_args_packets',
                                            {
                                                title: 'Extract SHE args packets',
                                                help: 'Extract SHE args packets from MAC prov frames',
                                                activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                content: '1 frame processed !',
                                                sheArgsTbl: contentHtml,
                                                accordionTab: 3
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
                
                /* ========================================================================================================================= */
                /* GET list_she_args_packets                                                                                                 */
                /* ========================================================================================================================= */
                router.get(
                    '/extract_she_args_packets',
                    (req, res, next) =>
                    {
                        console.log("*** GET /extract_she_args_packets");
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;

                                // Cut Prov frame in 2 64 bytes packets: MSB -> M1, LSB -> M2
                                var stmt = "SELECT id, Frame FROM MACProvFrames WHERE SHECmdExtracted = 0";
                                keystoredb.all(
                                    stmt,
                                    [],
                                    (err, rows) =>
                                    {
                                        var she = new decSHE();
                                        var ix;
                                        var contentHtml = "[";
                                        
                                        rows.forEach(
                                            (row, ix) =>
                                            {
                                                var SHE_m2 = row.Frame.substring(32, 64);
                                                var bufferM2 = Buffer.from(SHE_m2);
                                                var bufferKMasterEcu = Buffer.from(activeKeys['kMasterEcu']);
                                                var bufM2 = she.decrypt_M2(bufferM2, bufferKMasterEcu);
                                                var cid = "0x" + she.getCID(bufM2);
                                                var fid = "0x" + she.getFID(bufM2);
                                                var macKey = "0x" + she.getKEY(bufM2).toString('hex');

                                                if (ix > 0 && ix < rows.length)
                                                    contentHtml += ",";
                                                contentHtml += "{m2:'" + bufM2.toString('hex') + "',";
                                                contentHtml += "cid:'" + cid + "',";
                                                contentHtml += "fid:'" + fid + "',";
                                                contentHtml += "key:'" + macKey + "'}";

                                                // Create records in DB and mark the frame SHE cmd args as extracted
                                                keystoredb.serialize(
                                                    () =>
                                                    {
                                                        keystoredb.run(
                                                            "UPDATE MACProvFrames SET SHECmdExtracted = 1 WHERE id = ?",
                                                            [row.id]
                                                        );
                                                        keystoredb.run(
                                                            "INSERT INTO SHEArgsPackets (MACProvFrameId, M2) VALUES (?, ?)",
                                                            [row.id, bufM2]
                                                        );
                                                        keystoredb.run(
                                                            "INSERT INTO MACKeys (MACProvFrameId, MacKey, cid, fid) VALUES (?, ?, ?, ?)",
                                                            [row.id, macKey, cid, fid]
                                                        );                                                    
                                                    }
                                                );
                                            }
                                        );
                                        contentHtml += "]";
                                        res.render(
                                            'extract_she_args_packets',
                                            {
                                                title: 'Extract SHE args packets',
                                                help: 'Extract SHE args packets from MAC prov frames',
                                                activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                content: rows.length + ' frames processed',
                                                sheArgsTbl: contentHtml,
                                                accordionTab: 3
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
                
                /* ========================================================================================================================= */
                /* GET list_she_args_packets                                                                                                 */
                /* ========================================================================================================================= */
                router.get(
                    '/list_she_args_packets',
                    (req, res, next) =>
                    {
                        console.log("*** GET /list_she_args_packets");
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;

                                keystoredb.all(
                                    "SELECT id, MACProvFrameId, M2, KeysExtracted FROM SHEArgsPackets",
                                    [],
                                    (err, rows) =>
                                    {
                                        var contentHtml = "";
                                        rows.forEach(
                                            (row, ix) =>
                                            {
                                                if (ix != 0)
                                                    contentHtml += ",";
                                                contentHtml +=
                                                    "{id:" + row.id + "," +
                                                    "frameId:" + row.MACProvFrameId + "," +
                                                    "m2:'" + row.M2.toString('hex') + "'," +
                                                    "keysExtracted:" + (row.KeysExtracted ? "true" : "false") + "}";
                                            }
                                        );
                                        res.render(
                                            'list_she_args_packets',
                                            {
                                                title: 'List stored SHE args packets',
                                                help: 'Table listing all SHE commands args stored in DB',
                                                activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                                sheArgsTbl: '[' + contentHtml + ']',
                                                accordionTab: 3
                                            }
                                        );
                                    }
                                );
                            }
                        );
                    }
                );
                
                /*
                 * ========================================================================================================================= *
                 *                                                                                                                           *
                 *                                               Processing of MAC keys                                                      *
                 *                                                                                                                           *
                 * ========================================================================================================================= *
                 */

                /* ========================================================================================================================= */
                /* GET /unwrap_mac_keys/:frameId                                                                                             */
                /* ========================================================================================================================= */
                router.get(
                    '/unwrap_mac_keys_from_frame/:frameId',
                    (req, res, next) =>
                    {
                        console.log("*** GET /unwrap_mac_keys_from_frame/:frameId");
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;

                                // 
                                // Unwrap key from frame
                                //
                                //var kMacEcu = "00000000000000000000000000000011";
                                //var kMasterEcu = "0153F7000099ED9F320451AA8A7D9707";
                                //var key_update_enc_c = "010153484500800000000000000000B0";
                                var frameIdParam = Number.parseInt(req.params['frameId']);
                                var renderParams = 
                                    {
                                        title: 'Unwrap MAC keys from a MAC Prov. Frame',
                                        help: 'Unwrap MAC keys provided in a MAC provisionning frame',
                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                        content: "",
                                        accordionTab: 4
                                    };
                                keystoredb.get(
                                    "SELECT Frame FROM MACProvFrames WHERE id = ?",
                                    [frameIdParam],
                                    (err, row) =>
                                    {
                                        if (err || row === undefined)
                                        {
                                            next(err.status || 500);
                                            return;
                                        }
                                        else
                                        {
                                            var she = new decSHE();
                                            var bufferFrame = Buffer.from(row.Frame);
                                            var bufferKMasterEcu = Buffer.from(activeKeys['kMasterEcu']);

                                            var bufM2 = she.decrypt_M2(bufferFrame, bufferKMasterEcu);
                                            var cid = "0x" + she.getCID(bufM2);
                                            var fid = "0x" + she.getFID(bufM2);
                                            var key = "0x" + she.getKEY(bufM2).toString('hex');

                                            renderParams['m2'] = "'" + bufM2.toString('hex') + "'";
                                            renderParams['cid'] = "'" + cid + "'";
                                            renderParams['fid'] = "'" + fid + "'";
                                            renderParams['key'] = "'" + key + "'";


                                            keystoredb.serialize(
                                                () =>
                                                {
                                                    keystoredb.run("UPDATE MACProvFrames SET SHECmdExtracted = 1 WHERE id = ?", [frameIdParam]);
                                                    keystoredb.run(
                                                        "INSERT INTO SHEArgsPackets (MACProvFrameId, M2) VALUES (?, ?)",
                                                        [frameIdParam, bufM2]
                                                    );
                                                    keystoredb.run(
                                                        "INSERT INTO MACKeys (MACProvFrameId, MacKey, cid, fid, IsMaster) VALUES (?, ?, ?, ?, 0)",
                                                        [frameIdParam, key, cid, fid]
                                                    );
                                                }
                                            );
                                        }
                                        res.render(
                                            'unwrap_mac_keys_from_frame',
                                            renderParams
                                        );
                                    }
                                );
                            }
                        );
                    }
                );

                /* ========================================================================================================================= */
                /* GET /show_unwrapped_frame/:frameId                                                                                        */
                /* ========================================================================================================================= */
                router.get(
                    '/show_unwrapped_frame/:frameId',
                    (req, res, next) =>
                    {
                        console.log("*** GET /show_unwrapped_frame/:frameId");
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;

                                // 
                                // Unwrap key from frame
                                //
                                //var kMacEcu = "00000000000000000000000000000011";
                                //var kMasterEcu = "0153F7000099ED9F320451AA8A7D9707";
                                //var key_update_enc_c = "010153484500800000000000000000B0";
                                var frameIdParam = Number.parseInt(req.params['frameId']);
                                var renderParams = 
                                    {
                                        title: 'Show unwrapped MAC Prov. Frame',
                                        help: 'Show unwrapped MAC provisionning frame',
                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                        content: "",
                                        accordionTab: 4
                                    };
                                keystoredb.get(
                                    "SELECT * FROM SHEArgsPackets WHERE MACProvFrameId = ?",
                                    [frameIdParam],
                                    (err, row) =>
                                    {
                                        if (err || row == undefined)
                                        {
                                            next(err.status || 500);
                                            return;
                                        }
                                        var she = new decSHE();
                                        var bufM2 = Buffer.from(row.M2);
                                        var cid = "0x" + she.getCID(bufM2);
                                        var fid = "0x" + she.getFID(bufM2);
                                        var key = "0x" + she.getKEY(bufM2).toString('hex');

                                        renderParams['m2'] = "'" + bufM2 + "'";
                                        renderParams['cid'] = "'" + cid + "'";
                                        renderParams['fid'] = "'" + fid + "'";
                                        renderParams['key'] = "'" + key + "'";

                                        console.log("m2 = " + bufM2);
                                        console.log("cid = " + cid);
                                        console.log("fid = " + fid);
                                        console.log("key = " + key);

                                        try
                                        {
                                            keystoredb.run("UPDATE MACProvFrames SET SHECmdExtracted = 1 WHERE id = ?", [frameIdParam]);
                                            keystoredb.run(
                                                "INSERT INTO MACKeys (MACProvFrameId, MacKey, cid, fid, IsMaster) VALUES (?, ?, ?, ?, 0)",
                                                [frameIdParam, key, cid, fid]
                                            );
                                        }
                                        catch (e)
                                        {
                                        }
                                        res.render(
                                            'unwrap_mac_keys_from_frame',
                                            renderParams
                                        );
                                    }
                                );
                            }
                        );
                    }
                );

                /*
                 * ========================================================================================================================= *
                 *                                                                                                                           *
                 *                                               Set / Reset active MAC keys                                                      *
                 *                                                                                                                           *
                 * ========================================================================================================================= *
                 */

                /* ========================================================================================================================= */
                /* GET /activate_keys/:kMacEcu/:kMasterEcu                                                                                   */
                /* ========================================================================================================================= */
                router.get(
                    '/activate_keys/:kMacEcu/:kMasterEcu',
                    function(req, res, next)
                    {
                        var kMacEcu = Buffer.from(req.params['kMacEcu'], 'hex').toString('hex');
                        var kMasterEcu = Buffer.from(req.params['kMasterEcu'], 'hex').toString('hex');
                        var activeKeys = new Object;
                        activeKeys['kMacEcu'] = kMacEcu;
                        activeKeys['kMasterEcu'] = kMasterEcu;
                        keystoredb.serialize(
                            () =>
                            {
                                keystoredb.get(
                                    "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                                    [kMacEcu],
                                    (err, row) =>
                                    {
                                        if (row != undefined)
                                        {
                                            keystoredb.run(
                                                "DELETE FROM ActiveKeys",
                                                []
                                            );
                                        }
                                        else
                                        {
                                            keystoredb.run(
                                                "INSERT INTO ActiveKeys (MacEcu, MasterEcu) VALUES (?, ?)",
                                                [kMacEcu, kMasterEcu],
                                            );
                                        }
                                    }
                                );
                            }
                        );
                        res.render(
                            'index',
                            {
                                title: 'MAC Prov Tool',
                                help: 'Tools for manipulating MAC keys, MAC provisionning CAN frames and SHE commands for Key provisionning from log files ',
                                activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                accordionTab: 0
                            }
                        );                                      
                    }
                );
                
                /* ========================================================================================================================= */
                /* GET /set_mac_keys                                                                                                         */
                /* ========================================================================================================================= */
                router.get(
                    '/set_mac_keys',
                    (req, res, next) =>
                    {
                        console.log("*** GET /set_mac_keys");
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.get(
                            "SELECT MacEcu, MasterEcu FROM ActiveKeys",
                            (err, key) =>
                            {
                                if (key != undefined)
                                {
                                    k_mac_ecu = key.MacEcu;
                                    k_master_ecu = key.MasterEcu;
                                }
                                activeKeys['kMacEcu'] = k_mac_ecu;
                                activeKeys['kMasterEcu'] = k_master_ecu;
                                res.render(
                                    'set_mac_keys',
                                    {
                                        title: 'Set MAC keys',
                                        help: 'Set active K_MAC_ECU and K_MASTER_ECU',
                                        
                                        activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                        accordionTab: 5
                                    }
                                );
                            }
                        );
                    }
                );

                /* ========================================================================================================================= */
                /* GET /reset_mac_keys                                                                                                       */
                /* ========================================================================================================================= */
                router.get(
                    '/reset_mac_keys',
                    (req, res, next) =>
                    {
                        console.log("*** GET /reset_mac_keys");
                        var activeKeys = new Object;
                        var k_mac_ecu = "Not Set !";
                        var k_master_ecu = "Not Set !";
                        keystoredb.run(
                            "DELETE FROM ActiveKeys"
                        );
                        
                        activeKeys['kMacEcu'] = k_mac_ecu;
                        activeKeys['kMasterEcu'] = k_master_ecu;
                        res.render(
                            'reset_mac_keys',
                            {
                                title: 'Reset MAC keys',
                                help: 'Reset active K_MAC_ECU and K_MASTER_ECU',
                                content: 'Active keys have been erased ! No active keys set...',
                                activeKeys: "{kMacEcu:'"+activeKeys['kMacEcu']+"',kMasterEcu:'"+activeKeys['kMasterEcu']+"'}",
                                accordionTab: 0
                            }
                        );
                    }
                );

                /*
                 * ========================================================================================================================= *
                 *                                                  The End !                                                                *
                 * ========================================================================================================================= *
                 */
            }
        }
    );


module.exports = router;
