Rails.application.routes.draw do

   root 'client#index'
   get 'register_server' => 'client#register_server'
   get 'register' => 'client#register'
   get 'angemeldet' => 'client#sign_in'
   post 'angemeldet' => 'client#sign_in'
   get 'nachricht_schicken' => 'client#nachricht_schicken'
   get 'nachricht_abholen' => 'client#nachricht_abholen'
   get 'nachrichten_abholen' => 'client#nachrichten_abholen'
   get 'destroy_single' => 'client#destroy_single'
   get 'destroy_all' => 'client#destroy_all'
   get 'destroy_user' => 'client#destroy_user'
   get 'logout' => 'client#logout'

end
