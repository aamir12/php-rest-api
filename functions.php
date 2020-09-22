<?php
  
   function responseHandler($message='',$data=''){
    http_response_code(200);
    $msg = json_encode(['status'=>true, 'message'=>$message,'data'=>$data]);
    echo $msg; exit;
   }

   function errorHandler($message,$errorCode='serverErr',$code=500){
      http_response_code($code);
      $msg = json_encode(['status'=>false, 'error'=>$message,'errorCode'=>$errorCode]);
      echo $msg; exit;
   }

   function setupReq($method){      
      if($_SERVER['REQUEST_METHOD'] !== $method) {
         errorHandler('Invalid Method','invalidMethod',400);
      }

      // $contentType= [
      //     'json'=> 'application/json',
      //     'file' => 'application/x-www-form-urlencoded'
      // ];

      // echo $_SERVER['CONTENT_TYPE'];
      // if($_SERVER['CONTENT_TYPE'] !== $contentType[$ct]) {
      //    errorHandler('Invalid Input','invalidInput');
      // }
   }

   

   function currDT(){
    $currdatetime = date("Y-m-d h:m:s");
    return $currdatetime;
   }

   function currD(){
    $currdate = date("Y-m-d");
    return $currdate;
   }


?>