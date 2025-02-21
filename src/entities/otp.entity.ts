import { Entity, PrimaryGeneratedColumn, Column, CreateDateColumn, UpdateDateColumn, ManyToOne } from 'typeorm';
import { User } from './user.entity';

@Entity('otp')
export class OtpEntity {
    @PrimaryGeneratedColumn('uuid')
    id?: string;

    @Column()
    otpCode?: string;

    @Column()
    email?: string;

    @Column({ type: 'timestamp' })
    expiresAt?: Date;

    @Column({ default: false })
    isVerified?: boolean;

    @ManyToOne(() => User, (user) => user.otps, { onDelete: 'CASCADE' })
    user?: User;
  
    @CreateDateColumn()
    createdAt?: Date;

    @UpdateDateColumn()
    updatedAt?: Date;
}
