# PREREQUISITES
- `Knowledge of PHP (version >= 7.1.3).`
- `Knowledge of Laravel (version 5.6.x).`
- `Composer is installed on your computer (version >= 1.3.2).`
- `Laravel installer is installed on your computer.`

# CREATE THE APPLICATION

```
$ laravel new multi-auth
$ cd multi-auth
```
# CREATE THE DATABASE
Open the .env file in your application directory and change the following section:

```
DB_CONNECTION=mysql
DB_HOST=127.0.0.1
DB_PORT=3306
DB_DATABASE=homestead
DB_USERNAME=homestead
DB_PASSWORD=secret
```
# CREATE MIGRATION FOR ADMINS
To make the admins table, run the following command:

```
$ php artisan make:migration create_admins_table
```
From the database/migrations directory, open the admins migrations file and edit it as follows:

```php
// database/migrations/<timestamp>_create_admins_table.php

[...]
public function up()
{
    Schema::create('admins', function (Blueprint $table) {
        $table->increments('id');
        $table->string('name');
        $table->string('email')->unique();
        $table->string('password');
        $table->boolean('is_super')->default(false);
        $table->rememberToken();
        $table->timestamps();
    });
}
[...]
```
# CREATE MIGRATION FOR WRITERS
To make the writers table, run the following command:

```
$ php artisan make:migration create_writers_table
```
Now, open the writers migrations file and edit it as follows:

```php
// database/migrations/<timestamp>_create_writers_table.php
[...]
public function up()
{
    Schema::create('writers', function (Blueprint $table) {
        $table->increments('id');
        $table->string('name');
        $table->string('email')->unique();
        $table->string('password');
        $table->boolean('is_editor')->default(false);
        $table->rememberToken();
        $table->timestamps();
    });
}
[...]
```

# MIGRATE THE DATABASE
Now that we have defined our tables, let us migrate the database:

```
$ php artisan migrate
```

# ADMIN MODEL
To make the model for the admins, run the following command:

```
$ php artisan make:model Admin
```
Open the Admin model in app/Admin.php and add the following:

```php
// app/Admin.php
<?php

namespace App;

use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;

class Admin extends Authenticatable
{
    use Notifiable;

    protected $guard = 'admin';

    protected $fillable = [
        'name', 'email', 'password',
    ];

    protected $hidden = [
        'password', 'remember_token',
    ];
}
```
# WRITERS MODEL
To make the model for the writers, run the following command:

```
$ php artisan make:model Writer
```
Then open the Writer model and replace with the following:

```php
// app/Writer.php
<?php

namespace App;

use Illuminate\Notifications\Notifiable;
use Illuminate\Foundation\Auth\User as Authenticatable;

class Writer extends Authenticatable
{
    use Notifiable;

    protected $guard = 'writer';

    protected $fillable = [
        'name', 'email', 'password',
    ];

    protected $hidden = [
        'password', 'remember_token',
    ];
}
```
# DEFINE THE GUARDS
Open config/auth.php and add the new guards edit as follows:

```php
// config/auth.php

<?php

[...]
'guards' => [
    [...]
    'admin' => [
        'driver' => 'session',
        'provider' => 'admins',
    ],
    'writer' => [
        'driver' => 'session',
        'provider' => 'writers',
    ],
],
[...]
```
Now, add the following to the providers array:

```php
// config/auth.php

[...]
'providers' => [
    [...]
    'admins' => [
        'driver' => 'eloquent',
        'model' => App\Admin::class,
    ],
    'writers' => [
        'driver' => 'eloquent',
        'model' => App\Writer::class,
    ],
],
[...]
```
# MODIFY LOGINCONTROLLER
Open the `LoginController` in `app/Http/Controllers/Auth ` and edit as follows:

```php
// app/Http/Controllers/Auth/LoginController.php

<?php

namespace App\Http\Controllers\Auth;

use App\Http\Controllers\Controller;
use Illuminate\Foundation\Auth\AuthenticatesUsers;
[...]
use Illuminate\Http\Request;
use Auth;
[...]
class LoginController extends Controller
{
    [...]
    public function __construct()
    {
        $this->middleware('guest')->except('logout');
        $this->middleware('guest:admin')->except('logout');
        $this->middleware('guest:writer')->except('logout');
    }
    [...]
}
```
Now, define the login for admins:

```php
// app/Http/Controllers/Auth/LoginController.php

[...]
public function showAdminLoginForm()
{
    return view('auth.login', ['url' => 'admin']);
}

public function adminLogin(Request $request)
{
    $this->validate($request, [
        'email'   => 'required|email',
        'password' => 'required|min:6'
    ]);

    if (Auth::guard('admin')->attempt(['email' => $request->email, 'password' => $request->password], $request->get('remember'))) {

        return redirect()->intended('/admin');
    }
    return back()->withInput($request->only('email', 'remember'));
}
[...]
```
Now, let us do the same thing but for the writers:

```php
// app/Http/Controllers/Auth/LoginController.php


[...]
public function showWriterLoginForm()
{
    return view('auth.login', ['url' => 'writer']);
}

public function writerLogin(Request $request)
{
    $this->validate($request, [
        'email'   => 'required|email',
        'password' => 'required|min:6'
    ]);

    if (Auth::guard('writer')->attempt(['email' => $request->email, 'password' => $request->password], $request->get('remember'))) {

        return redirect()->intended('/writer');
    }
    return back()->withInput($request->only('email', 'remember'));
}
[...]
```
# MODIFY REGISTERCONTROLLER
Open the `RegisterController` and edit as follows:

```php
// app/Http/Controllers/Auth/RegisterController.php

<?php
[...]
namespace App\Http\Controllers\Auth;
use App\User;
use App\Admin;
use App\Writer;
use App\Http\Controllers\Controller;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Foundation\Auth\RegistersUsers;
use Illuminate\Http\Request;
[...]
class RegisterController extends Controller
{
    [...]
    public function __construct()
    {
        $this->middleware('guest');
        $this->middleware('guest:admin');
        $this->middleware('guest:writer');
    }
  [...]
}
```
Now, let us set up the methods to return the registration pages for the different users:

```php
// app/Http/Controllers/Auth/RegisterController.php

[...]
public function showAdminRegisterForm()
{
    return view('auth.register', ['url' => 'admin']);
}

public function showWriterRegisterForm()
{
    return view('auth.register', ['url' => 'writer']);
}
[...]
```

Now, we can define our methods for creating an admin:

```php
// app/Http/Controllers/Auth/RegisterController.php

[...] 
protected function createAdmin(Request $request)
{
    $this->validator($request->all())->validate();
    $admin = Admin::create([
        'name' => $request['name'],
        'email' => $request['email'],
        'password' => Hash::make($request['password']),
    ]);
    return redirect()->intended('login/admin');
}
[...] 
```

Next, let us define methods for creating a writer:

```php
// app/Http/Controllers/Auth/RegisterController.php

[...] 
protected function createWriter(Request $request)
{
    $this->validator($request->all())->validate();
    $writer = Writer::create([
        'name' => $request['name'],
        'email' => $request['email'],
        'password' => Hash::make($request['password']),
    ]);
    return redirect()->intended('login/writer');
}
[...] 
```

# SET UP AUTHENTICATION PAGES

```
$ php artisan make:auth
```

Open the `login.blade.php` file and edit as follows:

```php
// resources/views/auth/login.blade.php
[...]
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header"> {{ isset($url) ? ucwords($url) : ""}} {{ __('Login') }}</div>

                <div class="card-body">
                    @isset($url)
                    <form method="POST" action='{{ url("login/$url") }}' aria-label="{{ __('Login') }}">
                    @else
                    <form method="POST" action="{{ route('login') }}" aria-label="{{ __('Login') }}">
                    @endisset
                        @csrf
    [...]
</div>
```

Open the `register.blade.php` file and edit as follows:

```php
// resources/views/auth/register.blade.php

[...]
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header"> {{ isset($url) ? ucwords($url) : ""}} {{ __('Register') }}</div>

                <div class="card-body">
                    @isset($url)
                    <form method="POST" action='{{ url("register/$url") }}' aria-label="{{ __('Register') }}">
                    @else
                    <form method="POST" action="{{ route('register') }}" aria-label="{{ __('Register') }}">
                    @endisset
                        @csrf
    [...]
</div>
```

# CREATE THE PAGES AUTHENTICATED USERS WILL ACCESS

```
$ touch resources/views/layouts/app.blade.php
$ touch resources/views/admin.blade.php
$ touch resources/views/writer.blade.php
$ touch resources/views/home.blade.php
```
Insert this code block into the `app.blade.php` file:

```php
<!DOCTYPE html>
<html lang="{{ str_replace('_', '-', app()->getLocale()) }}">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1">

    <!-- CSRF Token -->
    <meta name="csrf-token" content="{{ csrf_token() }}">

    <title>{{ config('app.name', 'Laravel') }}</title>

    <!-- Scripts -->
    <script src="{{ asset('js/app.js') }}" defer></script>

    <!-- Fonts -->
    <link rel="dns-prefetch" href="https://fonts.gstatic.com">
    <link href="https://fonts.googleapis.com/css?family=Raleway:300,400,600" rel="stylesheet" type="text/css">

    <!-- Styles -->
    <link href="{{ asset('css/app.css') }}" rel="stylesheet">
</head>
<body>
    <div id="app">
        <nav class="navbar navbar-expand-md navbar-light navbar-laravel">
            <div class="container">
                <a class="navbar-brand" href="{{ url('/') }}">
                    {{ config('app.name', 'Laravel') }}
                </a>
                <button class="navbar-toggler" type="button" data-toggle="collapse" data-target="#navbarSupportedContent" aria-controls="navbarSupportedContent" aria-expanded="false" aria-label="{{ __('Toggle navigation') }}">
                    <span class="navbar-toggler-icon"></span>
                </button>

                <div class="collapse navbar-collapse" id="navbarSupportedContent">
                    <!-- Left Side Of Navbar -->
                    <ul class="navbar-nav mr-auto">

                    </ul>

                    <!-- Right Side Of Navbar -->
                    <ul class="navbar-nav ml-auto">
                        <!-- Authentication Links -->
                        @if(Auth::guard('admin')->check())
                        <li class="nav-item dropdown">
                            <a id="navbarDropdown" class="nav-link dropdown-toggle" href="#" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" v-pre>
                             {{Auth::guard('admin')->user()->name}} <span class="caret"></span>
                            </a>

                            <div class="dropdown-menu dropdown-menu-right" aria-labelledby="navbarDropdown">
                                <a class="dropdown-item" href="{{ route('logout') }}"
                                   onclick="event.preventDefault();
                                                 document.getElementById('logout-form').submit();">
                                    {{ __('Logout') }}
                                </a>

                                <form id="logout-form" action="{{ route('logout') }}" method="POST" style="display: none;">
                                    @csrf
                                </form>
                            </div>
                        </li>

                        @elseif(Auth::guard('writer')->check())
                        <li class="nav-item dropdown">
                            <a id="navbarDropdown" class="nav-link dropdown-toggle" href="#" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" v-pre>
                            {{Auth::guard('writer')->user()->name}} <span class="caret"></span>
                            </a>

                            <div class="dropdown-menu dropdown-menu-right" aria-labelledby="navbarDropdown">
                                <a class="dropdown-item" href="{{ route('logout') }}"
                                   onclick="event.preventDefault();
                                                 document.getElementById('logout-form').submit();">
                                    {{ __('Logout') }}
                                </a>

                                <form id="logout-form" action="{{ route('logout') }}" method="POST" style="display: none;">
                                    @csrf
                                </form>
                            </div>
                        </li>

                        @elseif(Auth::guard()->check())
                        <li class="nav-item dropdown">
                            <a id="navbarDropdown" class="nav-link dropdown-toggle" href="#" role="button" data-toggle="dropdown" aria-haspopup="true" aria-expanded="false" v-pre>
                            {{Auth::user()->name}} <span class="caret"></span>
                            </a>

                            <div class="dropdown-menu dropdown-menu-right" aria-labelledby="navbarDropdown">
                                <a class="dropdown-item" href="{{ route('logout') }}"
                                   onclick="event.preventDefault();
                                                 document.getElementById('logout-form').submit();">
                                    {{ __('Logout') }}
                                </a>

                                <form id="logout-form" action="{{ route('logout') }}" method="POST" style="display: none;">
                                    @csrf
                                </form>
                            </div>
                        </li>
                        @endif

                    </ul>
                </div>
            </div>
        </nav>

        <main class="py-4">
            @yield('content')
        </main>
    </div>
</body>
</html>
```
Next, insert this code block into the `admin.blade.php` file:

```php
// resources/views/admin.blade.php

@extends('layouts.auth')

@section('content')
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">Dashboard</div>

                <div class="card-body">
                    Hi boss!
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
```
Open the `writer.blade.php` file and edit as follows:

```php
// resources/views/writer.blade.php

@extends('layouts.auth')

@section('content')
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">Dashboard</div>

                <div class="card-body">
                    Hi there, awesome writer
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
```
Finally, open the `home.blade.php` file and replace with the following:

```php
// resources/views/home.blade.php

@extends('layouts.auth')

@section('content')
<div class="container">
    <div class="row justify-content-center">
        <div class="col-md-8">
            <div class="card">
                <div class="card-header">Dashboard</div>

                <div class="card-body">
                     Hi there, regular user
                </div>
            </div>
        </div>
    </div>
</div>
@endsection
```

# SET UP THE ROUTES
Our application is almost ready. Let us define the routes to access all the pages we have created so far. Open the `routes/web.php` file and replace with the following:

```php
<?php

Route::get('/', function () {
    return view('welcome');
});

Auth::routes();

Route::get('/home', 'HomeController@index')->name('home');

Route::get('/login/admin', 'Auth\LoginController@showAdminLoginForm');
Route::get('/login/writer', 'Auth\LoginController@showWriterLoginForm');
Route::get('/register/admin', 'Auth\RegisterController@showAdminRegisterForm');
Route::get('/register/writer', 'Auth\RegisterController@showWriterRegisterForm');

Route::post('/login/admin', 'Auth\LoginController@adminLogin');
Route::post('/login/writer', 'Auth\LoginController@writerLogin');
Route::post('/register/admin', 'Auth\RegisterController@createAdmin');
Route::post('/register/writer', 'Auth\RegisterController@createWriter');

Route::view('/home', 'home')->middleware('auth');
Route::view('/admin', 'admin')->middleware('auth:admin');
Route::view('/writer', 'writer')->middleware('auth:writer');
```

# MODIFY HOW OUR USERS ARE REDIRECTED IF AUTHENTICATED
open the `app/Http/Controllers/Middleware/RedirectIfAuthenticated.php` file and replace with this:

```php
// app/Http/Controllers/Middleware/RedirectIfAuthenticated.php

<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Support\Facades\Auth;

class RedirectIfAuthenticated
{
    public function handle($request, Closure $next, $guard = null)
    {
        if ($guard == "admin" && Auth::guard($guard)->check()) {
            return redirect('/admin');
        }
        if ($guard == "writer" && Auth::guard($guard)->check()) {
            return redirect('/writer');
        }
        if (Auth::guard($guard)->check()) {
            return redirect('/home');
        }

        return $next($request);
    }
}
```

# MODIFY AUTHENTICATION EXCEPTION HANDLER
To ensure that when a user tries to visit `/writer` they are redirected to `/login/writer` or the same for `/admin`, 
we have to modify the exception handler. Open the handler file in `app/Exceptions` and add the following:

```php
// app/Exceptions/Handler.php

<?php

namespace App\Exceptions;

use Exception;
use Illuminate\Foundation\Exceptions\Handler as ExceptionHandler;
[...]
use Illuminate\Auth\AuthenticationException;
use Auth; 
[...]
class Handler extends ExceptionHandler
{
   [...] 
    protected function unauthenticated($request, AuthenticationException $exception)
    {
        if ($request->expectsJson()) {
            return response()->json(['error' => 'Unauthenticated.'], 401);
        }
        if ($request->is('admin') || $request->is('admin/*')) {
            return redirect()->guest('/login/admin');
        }
        if ($request->is('writer') || $request->is('writer/*')) {
            return redirect()->guest('/login/writer');
        }
        return redirect()->guest(route('login'));
    }
}
```

# RUN THE APPLICATION

```
$ php artisan serve
```
It should typically be available on `http://localhost:8000`.
