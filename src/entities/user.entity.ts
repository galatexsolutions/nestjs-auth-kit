import { Entity, PrimaryGeneratedColumn, Column, OneToMany } from 'typeorm';
import { OtpEntity } from './otp.entity';

@Entity()
export class User {
    @PrimaryGeneratedColumn()
    id?: string;

    @Column()
    firstName?: string;

    @Column()
    lastName?: string;

    @Column()
    email?: string;

    @Column()
    password?: string;

    @Column('simple-array', { nullable: true })
    roles?: string[];

    @OneToMany(() => OtpEntity, (otp) => otp.user)
    otps?: OtpEntity[];
}
