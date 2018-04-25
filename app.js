angular.module('security-ques', ['ngAnimate', 'ui.bootstrap', 'ngRoute'])
.config(['$routeProvider', function($routeProvider){
    $routeProvider
        .when('/', {
            templateUrl: 'qa.html',
            controller: ['$scope', function($scope){
                $scope.page = 'home';
            }]
        })
        .when('/about', {
            template: '<h2>{{page}}</h2>',
            controller: ['$scope', function($scope){
                $scope.page = 'about';
            }]
        })
        .otherwise({redirectTo: '/'});
}]);