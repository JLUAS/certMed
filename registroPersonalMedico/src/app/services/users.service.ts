import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Router } from 'express';
import { BehaviorSubject, Observable } from 'rxjs';
import { UserLogin, UserRegister } from '../models/User';

@Injectable({
  providedIn: 'root'
})
export class UsersService {

  private apiUrl = 'http://localhost:3030';

  constructor(private http: HttpClient) { }

  private hasToken(): boolean {
    return !!localStorage.getItem('token');
  }

  login(user: UserLogin): Observable<any> {
    return this.http.get(`${this.apiUrl}/login`);
  }

  register(user: UserRegister): Observable<any> {
    return this.http.post(`${this.apiUrl}/register`, user);
  }
}
