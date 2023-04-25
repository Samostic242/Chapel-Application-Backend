<?php

namespace App\Http\Controllers\Authentication;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Tzsk\Otp\Facades\Otp;
use App\Http\Mail\validateEmail as emailVerify;
use App\Mail\signup;
use App\Mail\validateEmail as MailValidateEmail;
use App\Models\User;
use Carbon\Carbon;
use Exception;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Validator;



class validateEmail extends Controller
{
    public function generateToken(Request $request)
    {
        $rule = ['email' => 'required|email|unique:users'];
        $messages = ['email.required' => "You can't leave email field empty",
                    'email.email' => 'Email field must be a valid email format',
                    'email.unique' => 'User with this email already exists'
        ];
        $validator = Validator::make($request->all(), $rule, $messages);
        if ($validator->fails()) {
            return response()->json([
                'status' => 'failed',
                'message' => 'The given data was invalid.',
                'errors' => $validator->errors()
            ], 422);
        };
        $otp = Otp::digits(5)->expiry(10)->generate($request->email);
        $data = [
            'token' => $otp,
            'email' => $request->email,
        ];
        Mail::send(new MailValidateEmail($data));

        return response()->json([
            'message' => 'One time token has been sent successfuly, it expires in 5 minutes',
            'data' => null,
            'token' => $otp,
            'error' => false
        ], 200);


    }

    public function verifyToken(Request $request)
    {
        $rule = ['email' => 'required|email|unique:users',
        'otp' => 'required|regex:/[0-9]{4}/'
    ];
    $messages = [
        'email.required' => "You can't leave email field empty",
        'email.email' => 'Email field must be a valid email format',
        'email.unique' => 'User with this email already exists',
        'otp.required' => "You can't leave otp field empty",
        'otp.regex' => "The field must be 5 digit long"
    ];
    $validator = Validator::make($request->all(), $rule, $messages);
    if ($validator->fails()) {
        return response()->json([
            'status' => 'failed',
            'message' => 'The given data was invalid.',
            'errors' => $validator->errors()
        ], 422);
    };

    $verify = Otp::digits(5)->expiry(10)->check($request->otp, $request->email);
    $access_token = Otp::digits(12)->expiry(10)->generate($request->email);
    if($verify)
    {
        return response()->json([
            'message' => 'One time password has been verified successfully',
            'data' => $access_token,
            'error' => false
        ], 200);
    }else{
        return response()->json([
            'message' => 'Invalid one time password',
            'data' => null,
            'error' => true
        ], 401);
    }

    }

    public function register(Request $request)
    {
        DB::beginTransaction();
        try{
            $validator = Validator::make($request->all(), [
                'full_name' => 'required|string|max:20',
                'email' => 'required|email|unique:users',
                'phone' => 'required|regex:/[0-9]{11}/|unique:users',
                'category' => 'required',
                'unit' => 'required',
                'department' => 'required',
                'password' => 'required|string|confirmed|min:6',
            ]);
            if($validator->fails()){
                return response()->json(
                    [
                        'status' => 'failed',
                        'message' => 'The given data was invalid.',
                        'errors' => $validator->errors()
                    ],
                    422
                );
            }
            if ($request->hasHeader("X-Access-Token")) {
                $access_token = $request->header("X-Access-Token");
                $verify = Otp::digits(12)->expiry(10)->check($access_token, $request->email);
                if (!$verify) {
                    return response()->json(['status' => 'failed', 'message' => 'invalid/expired access_token'], 409);
                }
            } else {
                return response()->json(['status' => 'failed', 'message' => 'access token missing in request header'], 409);
            }

            $validated_data = $validator->validated();
            $user = User::create(array_merge($validated_data, ['password' => Hash::make($request->password), 'email_verified_at' => Carbon::now()]));
            if($user->exists())
            {
                $crendetials = ['email' => $user->email, 'password' => $request->password];
                $token = auth()->attempt($crendetials, true);
                DB::commit();
                Mail::send(new signup($user));
                return response()->json([
                    'message' => 'User has been registered successfully',

                    'data'=> [
                        'token' => $token,
                        'user' => $user
                    ],
                    'error' => false,
                ], 200);
            }
        }
            catch (Exception $e) {
                DB::rollBack();
                return response()->json([
                    'status' => 'failed',
                    'message' => $e->getMessage(),
                    'error' => true
                ], 400);

            }
    }

    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|email',
            'password' => 'required|string|min:6',
        ]);
        if ($validator->fails()) {
            return response()->json($validator->errors(), 422);
        }
        if (! $token = auth()->attempt($validator->validated())) {
            return response()->json(['error' => 'Unauthorized'], 401);
        }
        return $this->createNewToken($token);
    }

    public function logout() {
        auth()->logout();
        return response()->json([
            'message' => 'User successfully signed out',
            'data' => null,
            'error' => false,
        ], 200);
    }


    protected function createNewToken($token){
        return response()->json([
            'access_token' => $token,
            'token_type' => 'bearer',
            'expires_in' => auth()->factory()->getTTL() * 60,
            'user' => auth()->user()
        ]);
    }


}
