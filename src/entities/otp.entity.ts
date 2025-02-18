import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn } from 'typeorm';

@Entity()
export class Otp {
    @PrimaryGeneratedColumn('uuid')
    id?: string;

    @Column()
    email?: string;

    @Column()
    otp?: string;

    @Column()
    expiresAt?: Date;

    @CreateDateColumn()
    createdAt?: Date;
}
