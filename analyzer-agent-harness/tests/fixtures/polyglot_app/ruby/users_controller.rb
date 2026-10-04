class UsersController < ApplicationController
  def show
    User.where("name = '#{params[:name]}'")
    system("ping -c 1 #{params[:host]}")
    eval(params[:code])
  end
end
