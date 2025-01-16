import { Component } from '@angular/core';
import { UserRegister } from '../../models/User';
import { UsersService } from '../../services/users.service';

@Component({
  selector: 'app-register',
  templateUrl: './register.component.html',
  styleUrl: './register.component.css'
})
export class RegisterComponent {

  constructor(private usersService: UsersService) {}

  user: UserRegister = { email: '', password: '', username: '', rol: '', auth: false, authCode: '', speciality: '', hSpeciality: '' };
  errMessage: string = "";
  errPassword: boolean = false;
  errUser: boolean = false;
  errGeneral: boolean = false;
  isLoading: boolean = false;
  passwordToggle: string = "password";

  togglePassword() {
    if (this.passwordToggle == "password") {
      this.passwordToggle = "text";
    } else {
      this.passwordToggle = "password";
    }
  }

  // Función para generar un código de autenticación aleatorio de 15 caracteres
  generateAuthCode(length: number = 15): string {
    const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let authCode = '';
    for (let i = 0; i < length; i++) {
      authCode += characters.charAt(Math.floor(Math.random() * characters.length));
    }
    return authCode;
  }

  register() {
    if (this.user.email != '' && this.user.password != '' && this.user.username != '' && this.user.username != "") {
      if (this.user.password.length < 8) {
        this.errMessage = "La contraseña debe de tener mínimo 8 caracteres";
        this.errPassword = true;
        this.errGeneral = false;
      } else if (this.user.username.length < 9) {
        this.errMessage = "Recuerda incluir nombre y ambos apellidos";
        this.errUser = true;
        this.errPassword = false;
        this.errGeneral = false;
      } else {
        if (this.user.rol == "admin") {
          this.user.speciality = "NA";
          this.user.hSpeciality = "NA";
        } else{
          this.user.speciality = "Pendiente";
          this.user.hSpeciality = "Pendiente";
        }

        // Generar el authCode antes de registrar al usuario
        this.user.authCode = this.generateAuthCode();

        // Llamar al servicio para registrar el usuario
        this.usersService.register(this.user).subscribe(
          (res: any) => {
            this.isLoading = false;
          },
          (err) => {
            this.isLoading = false;
            this.errPassword = false;
            this.errMessage = 'Error al agregar administrador';
            console.error(err);
          }
        );
      }
    } else {
      this.errPassword = false;
      this.errGeneral = true;
      this.errMessage = "Llena todos los campos";
    }
  }

}
