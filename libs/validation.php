<?php
  class validation extends DB {

    public $alldata= NULL;

    public function __construct(){
        parent::__construct();
    }

    public function required($data){
        if(isset($this->alldata[$data])){        
            if(empty($this->alldata[$data]) || trim($this->alldata[$data])==''){
                return true;  
            }
            return false;
        }else{
            return true;
        }
    }

    public function email($data){
        if (!filter_var($this->alldata[$data], FILTER_VALIDATE_EMAIL)) {
           return true;
        }
        return false;
    }

    public function unique($ele){
       $val = $this->alldata[$ele[0]] ;
       $config = explode('|',$ele[3]);
       $tabconfig = explode('.',$config[0]);

       if(isset($config[1])){
        return false; //edit mode
       }else{
         $check = $this->getRows(
             $tabconfig[0],
             ['where'=>[$tabconfig[1]=>$val],'return_type'=>'single']
         );

         if($check){
             return true;
         }else{
             return false;
         }


       }
       
    }

    public function validated($data,$config){
        
        $this->alldata = $data;
        $validation = [
            'valid' => true,
            'errors'=>[]
        ];

       if(count($config)>0){
        foreach($config as $ckey => $ele){
           
            $rules = explode('|',$ele[1]);
            $status = false;
            foreach($rules as $rkey => $r){
                switch($r){
                    case  'required' : 
                     $status  = $this->required($ele[0]);
                     break;
                    
                    case  'email' : 
                     $status  = $this->email($ele[0]);
                     break;

                    case 'unique' : 
                     $status =  $this->unique($ele);    
                }
                if($status){
                    $messages = explode('|',$ele[2]);
                    $validation['valid'] = false;
                    array_push($validation['errors'],$messages[$rkey]);
                    break;
                }
            }
            
        }
        
       }
    
       return $validation;

    }

  }

?>