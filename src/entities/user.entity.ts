import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from 'typeorm';
import { OtpEntity } from './otp.entity';

@Entity()
export class User {
    @PrimaryGeneratedColumn('uuid')
    id?: string;

    @Column()
    email?: string;

    @Column()
    password?: string;

    @Column('simple-array')
    roles?: string[];

    @OneToMany(() => OtpEntity, (otp) => otp.user)
    otps?: OtpEntity[];
}
