Main api file is api.php

Index  : 1
validation
========================
<?php

$v = new validation();
$config = [
    [
        'id',
        'required|email|unique', //sequence of rules important for evaluation
        'Id is required|Invalid email id|Already exist', //according to rules
        'author.email' //only when unique
    ]
];
$check = $v->validated($data,$config);
if(!$check['valid']){
    errorHandler($check['errors'],'notValid',400);
}
//end of validation


?>

Index : 2
Error Codes
====================

noReq   :  Request denied (no action define)
notAuth : Unauthorized access
unknownReq : Unknown Request (no matching action)
invalidToken : Access denied
sessionExpr : Session expired
notValid :  set of errors in array
invalidMethod : Invalid Method (GET PUT DELETE PUT)
invalidAuth : Invalid username or password
notFound : Not Found (not matching id)
serverErr : Server Error 

