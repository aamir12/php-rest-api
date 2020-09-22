<?php
class auth_mdl extends DB{

    public function __construct(){
      parent::__construct();
    }

    public function create($data){
      $data['password'] = md5($data['password']);
      $result = $this->insert('author',$data);
      return $result;
    }

    public function single($id){
       $result = $this->getRows('author',['where'=>['aid'=>$id],'return_type'=>'single']);
       return $result;
    }

    public function login($email,$password){
      $result = $this->getRows('author',['where'=>['email'=>$email,'password'=>md5($password)],'return_type'=>'single']);
      return $result;
    }
}


?>