angular.module('security-ques', ['ngAnimate', 'ui.bootstrap', 'ngRoute'])
.config(['$routeProvider', function($routeProvider){
    $routeProvider
        .when('/', {
            templateUrl: 'qa.html'
        })
        .when('/download', {
            templateUrl: 'download.html'
        })
        .otherwise({redirectTo: '/'});
}]);