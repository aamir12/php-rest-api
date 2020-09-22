<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>File Upload</title>
    <script src="https://code.jquery.com/jquery-3.4.1.min.js"></script>

</head>
<body>

<form id="form"   method="post" enctype="multipart/form-data">
NAME
<input type="text" class="form-control" id="name" name="name" placeholder="Enter name" required />
<input type="text"  id="id" name="id" value="1" />
<input id="file" type="file" accept="image/*" name="file" />
<input class="btn btn-success" type="submit" value="Upload">
</form>

<br>
<form id="form1"  >
ID
<input type="text"  id="id" name="id" value="1" />
<input class="btn btn-success" type="submit" value="Upload">
</form>

    
</body>

<script>
  $(document).ready(function(e){
    // Submit form data via Ajax
    $("#form").on('submit', function(e){
        e.preventDefault();
        $.ajax({
            type: 'POST',
            url: 'http://localhost/myrestapi/api.php?action=addPost',
            data: new FormData(this),
            dataType: 'json',
            contentType: false,
            cache: false,
            processData:false,
            success: function(response){ 
                console.log(response.status);
            }
        });
    });

    $("#form1").on('submit', function(e){
        e.preventDefault();
        let id = $("#id").val();
        $.ajax({
            type: 'GET',
            url: 'http://localhost/myrestapi/api.php?action=getCategory',
            data: {id:id},
            dataType: 'json',
            success: function(response){ 
                console.log(response.status);
            },
            error: function (jqXHR) {
                console.log(jqXHR.responseJSON.errorCode);
            }
        });
    });

});
</script>
</html>