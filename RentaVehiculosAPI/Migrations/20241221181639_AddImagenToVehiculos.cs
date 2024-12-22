using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace RentaVehiculosAPI.Migrations
{
    public partial class AddImagenToVehiculos : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<int>(
                name: "Asientos",
                table: "Vehiculos",
                type: "int",
                nullable: false,
                defaultValue: 0);

            migrationBuilder.AddColumn<string>(
                name: "Color",
                table: "Vehiculos",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");

            migrationBuilder.AddColumn<byte[]>(
                name: "Imagen",
                table: "Vehiculos",
                type: "varbinary(max)",
                nullable: false,
                defaultValue: new byte[0]);

            migrationBuilder.AddColumn<string>(
                name: "Placa",
                table: "Vehiculos",
                type: "nvarchar(max)",
                nullable: false,
                defaultValue: "");
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropColumn(
                name: "Asientos",
                table: "Vehiculos");

            migrationBuilder.DropColumn(
                name: "Color",
                table: "Vehiculos");

            migrationBuilder.DropColumn(
                name: "Imagen",
                table: "Vehiculos");

            migrationBuilder.DropColumn(
                name: "Placa",
                table: "Vehiculos");
        }
    }
}
