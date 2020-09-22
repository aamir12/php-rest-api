<?php

  // Headers
  header('Access-Control-Allow-Origin: *');
  header('Content-Type: application/json; charset:utf-8');
  header('Access-Control-Allow-Methods: POST,GET,PUT,DELETE');
  header('Access-Control-Allow-Headers: Access-Control-Allow-Headers,Content-Type,Access-Control-Allow-Methods, Authorization, X-Requested-With');

 
  require_once('constant.php'); 
  require_once('functions.php');
  require_once('db.php');
  require_once('libs/validation.php');
  require_once('libs/jwt.php');
  require_once('model/auth_mdl.php');
    
  $action = isset($_REQUEST['action'])?trim($_REQUEST['action']) : '';  
  
   switch ($action)
    {
        case 'login':

            login($_REQUEST);
            break;
        case 'registration':
            registration($_REQUEST);
            break;
        case 'getCategory':
            getCategory($_REQUEST);
            break;

        case 'addPost':            
            addPost($_REQUEST);
            break;

        case 'sample':            
            sample($_REQUEST);
            break;

        case '':            
            errorHandler('Request denied','noReq');            

        default:
        errorHandler('Unknown Request','unknownReq');
    }



    /*******TOKEN*********/

    function getAuthorizationHeader(){
        $headers = null;
        if (isset($_SERVER['Authorization'])) {
            $headers = trim($_SERVER["Authorization"]);
        }
        else if (isset($_SERVER['HTTP_AUTHORIZATION'])) { //Nginx or fast CGI
            $headers = trim($_SERVER["HTTP_AUTHORIZATION"]);
        } elseif (function_exists('apache_request_headers')) {
            $requestHeaders = apache_request_headers();
            // Server-side fix for bug in old Android versions (a nice side-effect of this fix means we don't care about capitalization for Authorization)
            $requestHeaders = array_combine(array_map('ucwords', array_keys($requestHeaders)), array_values($requestHeaders));
            if (isset($requestHeaders['Authorization'])) {
                $headers = trim($requestHeaders['Authorization']);
            }
        }
        return $headers;
    }


    function getBearerToken() {
        $headers = getAuthorizationHeader();
        // HEADER: Get the access token from the header
        if (!empty($headers)) {
            //it is only conception
            // if (preg_match('/Bearer\s(\S+)/', $headers, $matches)) {
            //     return $matches[1];
            // }
            return $headers;
        }        
        errorHandler('Unauthorized access','notAuth',404);
    }

    function auth(){
        try {
            $token = getBearerToken();
            $author = new auth_mdl();
            $payload = JWT::decode($token, SECRETE_KEY, ['HS256']);
            $result = $author->single($payload->userId);

            if(!$result) {
                errorHandler('Access denied','invalidToken',404);
            }

            $userId = $payload->userId;
        } catch (Exception $e) {
            errorHandler('Session Expired','sessionExpr',404);
        }

    }

    /******End of Token****/


    /*******Login and registration********/ 
    //login and generate token
    //method : POST
    //@body : email | password
    function login($data){
        //only POST method will allow for this api
        setupReq('POST'); 
        //validation 
        $v = new validation();
        $config = [
            [
                'email',
                'required|email',
                'Email is required|Invalid email id'
            ],
            [
                'password',
                'required',
                'Password is required'
            ]
        ];
        $check = $v->validated($data,$config);
        if(!$check['valid']){
            errorHandler($check['errors'],'notValid',400);
        }

        $author = new auth_mdl();
        $result = $author->login($data['email'],$data['password']);
        if($result){
          
            $paylod = [
                'iat' => time(),
                'iss' => JWT_ISS,
                'exp' => time() + (15*60),
                'userId' => $result['aid']
            ];

            $token = JWT::encode($paylod, SECRETE_KEY);
            $data = ['token' => $token];
            responseHandler('Login Successfully',$data);

        }else{
            errorHandler('Invalid username or password','invalidAuth',404);
        }


    }

     //registration
    //method : POST
    //@body : email | password | name

    function registration($data){
        setupReq('POST');
        //validation 
        $v = new validation();
        $config = [
            [
                'name',
                'required',
                'Name is required'
            ],
            [
                'email',
                'required|email|unique',
                'Email is required|Invalid email id|Email id already exist',
                'author.email'
            ],
            [
                'password',
                'required',
                'Password is required'
            ]
        ];
        $check = $v->validated($data,$config);
        if(!$check['valid']){
            errorHandler($check['errors'],'notValid',400);
        }

        $author = new auth_mdl();
        unset($data['action']); // action is not a column in DB
        $result = $author->create($data);
        if($result){
            responseHandler('Register Successfully',['id'=>$result]);
        }else{
            errorHandler('Server Error');
        }


    }


    
    /**Start Category **/   

    //get single category
    //method : GET
    //url: URL?action=getCategory
    //@body : id
    function getCategory($data){
        setupReq('GET');
        auth(); // token based authorization
        $v = new validation();
        $config = [
            [
                'id',
                'required',
                'Id is required'
            ]
        ];
        $check = $v->validated($data,$config);
        if(!$check['valid']){
            errorHandler($check['errors'],'notValid',400);
        }

        require_once('model/category_mdl.php');
        $category = new category_mdl();
        $result = $category->single($data['id']);
        

        if($result){
            responseHandler('get Successfully',$result);
        }else{
            errorHandler('Not Found','notFound',404);
        }
    }

    /******************/
    /*End of Category*/
    /****************/





    /*************/
    /* Start post */
    /************/

    //add post
    //method : POST
    //url: URL?action=addPost
    //@body : category_id/title/body/author/
    function addPost($data){
        setupReq('POST');

        //upload photo here
        if(isset($_FILES['file'])){
           
        }

        
       
        responseHandler('get Successfully',$data);
    }


    /*************/
    /*End of Post*/
    /************/
 

    function sample($data){
   	    $postdata    = file_get_contents("php://input");
   	    if(isset($postdata) && !empty($postdata)){
		   	$request     = json_decode($postdata,true);
		    echo $request['address']['state'];
        }
    }
    
  



?>