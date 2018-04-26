angular.module('security-ques').controller('DownloadCtrl', function ($scope, $http) {
   

    $scope.generatePDF = function(json) {
        var doc = new jsPDF();
        doc.setFontSize(12)
        doc.text(15, 10, 'Project Name : '+json.projectName);
        doc.text(15, 15, 'Manager Name : '+json.managerName);

        var j = 15;
        json.standards.forEach(function(standard, i){
            doc.text(15,j=j+10, "Q): " + standard.Question);
            doc.text(20, j=j+10,  standard.Ans);
        });

        doc.save(json.projectName+'_'+json.date+'.pdf');
    }
    
    $http.get('http://localhost:8080/security-standard')
    .then(function(result) {
       $scope.qaList = result.data;
      }, function() {
       
      }
    );
});