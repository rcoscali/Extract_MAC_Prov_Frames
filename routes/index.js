var express = require('express');
var router = express.Router();
var mime = require('mime');
var reader = require ("buffered-reader");
var formidable = require('formidable');
var path = require('path');
var fs = require('fs');
const bodyParser = require("body-parser");
const sqlite3 = require('sqlite3').verbose();
const {exec} = require("child_process");
var app = require('../app');

// Instanciate keystore DB
var keystoredb =
    new sqlite3.Database(
        '/home/rcoscali/Public/MAC_Prov_Extract/var/lib/keystore.db',
        sqlite3.OPEN_READWRITE | sqlite3.OPEN_FULLMUTEX | sqlite3.OPEN_PRIVATECACHE,
        (err) =>
        {
            if (err)
            {
                console.error(err.message);
                process.exit(1);
            }
            else {
                console.log('****** Keys DB openned !');

                var app = express();

		/* GET home page. */
		router.get('/', function(req, res, next) {
		    res.render('index', { title: 'MAC Prov Tool' });
		});

		/*
		 * Log Files functions
		 */
		
		/* GET import_log_file. */
		router.get('/import_log_file', function(req, res, next) {
		    res.render('import_log_file',
			       {
				   title: 'Import a log file',
				   help: 'Import a log file and store it in DB',
				   accordionTab: 0
			       });
		});
		
		/* GET list_log_file. */
		router.get('/list_log_file', function(req, res, next) {
		    res.render('list_log_file',
			       {
				   title: 'List stored log file',
				   help: '',
				   accordionTab: 0
			       });
		});
		
		/* GET delete_log_files. */
		router.get('/delete_log_files', function(req, res, next) {
		    res.render('delete_log_files',
			       {
				   title: 'Delete stored log files',
				   help: 'Delete LOG files stored in DB (record & files)',
				   accordionTab: 0
			       });
		});
		
		/* GET extract_mac_frames. */
		router.get('/extract_mac_frames', function(req, res, next) {
		    res.render('extract_mac_frames',
			       {
				   title: 'Extract MAC Prov. frames',
				   help: 'Extract MAC provisionning frames from an uploaded log file',
				   accordionTab: 1
			       });
		});
		
		/* GET list_mac_prov_frame. */
		router.get('/list_mac_prov_frame', function(req, res, next) {
		    res.render('list_mac_prov_frame',
			       {
				   title: 'List stored MAC prov frames',
				   help: 'List stored MAC Provisionning frames found in log files',
				   accordionTab: 1
			       });
		});
		
		/* GET list_she_args_packets. */
		router.get('/extract_she_args_packets', function(req, res, next) {
		    res.render('extract_she_args_packets',
			       {
				   title: 'Extract SHE args packets',
				   help: 'Extract SHE args packets from MAC prov frames',
				   accordionTab: 2
			       });
		});
		
		/* GET list_she_args_packets. */
		router.get('/list_she_args_packets', function(req, res, next) {
		    res.render('list_she_args_packets',
			       {
				   title: 'List stored SHE args packets',
				   help: '',
				   accordionTab: 2
			       });
		});
		
		/* GET unwrap_mac_keys. */
		router.get('/unwrap_mac_keys', function(req, res, next) {
		    res.render('unwrap_mac_keys',
			       {
				   title: 'Unwrap MAC keys provided in a selected SHE args packets',
				   help: '',
				   accordionTab: 2
			       });
		});
	    }
	});
	
module.exports = router;
