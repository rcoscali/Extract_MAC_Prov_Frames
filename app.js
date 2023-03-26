var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var bodyParser = require('body-parser');
var logger = require('morgan');

var indexRouter = require('./routes/index');

var app = express();
app.use('/', indexRouter);

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.use(logger('dev'));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'pug');

app.use(express.json());
app.use(cookieParser());

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));


// catch 404 and forward to error handler
app.use(
    (req, res, next) =>
    {
        console.log("Intercept err 404 !");
        next(createError(404));
    }
);

// error handler
app.use(
    (err, req, res, next) =>
    {
        // set locals, only providing error in development
        res.locals.message = err.message;
        res.locals.error = req.app.get('env') === 'development' ? err : {};
      
        // render the error page
        console.log(new Error().stack);
        
        res.status(err.status || 500);
        res.render(
            'error',
            {
                error_message: err.message,
                error_status: err.status,
                error_stack: err.stack
            }
        );
    }
);

module.exports = app;
