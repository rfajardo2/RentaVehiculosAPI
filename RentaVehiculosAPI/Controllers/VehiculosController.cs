namespace RentaVehiculosAPI.Controllers
{
    using Microsoft.AspNetCore.Authorization;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.EntityFrameworkCore;
    using RentaVehiculosAPI.Data;
    using RentaVehiculosAPI.Models;

    [Authorize]
    [Route("api/[controller]")]
    [ApiController]
    public class VehiculosController : ControllerBase
    {
        private readonly AppDbContext _context;

        public VehiculosController(AppDbContext context)
        {
            _context = context;
        }

        [HttpGet]
        public IActionResult GetVehiculos()
        {
            var vehiculos = _context.Vehiculos.ToList();
            var result = vehiculos.Select(v => new VehiculoDto
            {
                Id = v.ID,
                Marca = v.Marca,
                Modelo = v.Modelo,
                Year = v.Year,
                Estado = v.Estado,
                TarifaPorHora = v.TarifaPorHora,
                PenalizacionPorHora = v.PenalizacionPorHora,
                Placa = v.Placa,
                Color = v.Color,
                Asientos = v.Asientos,
                ImagenBase64 = v.Imagen != null ? Convert.ToBase64String(v.Imagen) : null
            }).ToList();

            return Ok(result);
        }


        [HttpGet("{id}")]
        public IActionResult GetVehiculo(int id)
        {
            var vehiculo = _context.Vehiculos.Find(id);
            if (vehiculo == null) return NotFound();
            return Ok(vehiculo);
        }

        [HttpPost]
        public IActionResult CreateVehiculo([FromBody] VehiculoDto vehiculoDto)
        {
            if (vehiculoDto == null) return BadRequest("Datos inválidos");

            var vehiculo = new Vehiculo
            {
                Marca = vehiculoDto.Marca,
                Modelo = vehiculoDto.Modelo,
                Year = vehiculoDto.Year,
                Estado = vehiculoDto.Estado,
                TarifaPorHora = vehiculoDto.TarifaPorHora,
                PenalizacionPorHora = vehiculoDto.PenalizacionPorHora,
                Placa = vehiculoDto.Placa,
                Color = vehiculoDto.Color,
                Asientos = vehiculoDto.Asientos,
                Imagen = !string.IsNullOrEmpty(vehiculoDto.ImagenBase64)
                         ? Convert.FromBase64String(vehiculoDto.ImagenBase64)
                         : null
            };

            _context.Vehiculos.Add(vehiculo);
            _context.SaveChanges();

            return Ok(new { message = "Vehículo creado correctamente" });
        }


        [HttpPut("{id}")]
        public IActionResult UpdateVehiculo(int id, [FromBody] VehiculoDto vehiculoDto)
        {
            var vehiculo = _context.Vehiculos.Find(id);
            if (vehiculo == null) return NotFound("Vehículo no encontrado");

            vehiculo.Marca = vehiculoDto.Marca;
            vehiculo.Modelo = vehiculoDto.Modelo;
            vehiculo.Year = vehiculoDto.Year;
            vehiculo.Estado = vehiculoDto.Estado;
            vehiculo.TarifaPorHora = vehiculoDto.TarifaPorHora;
            vehiculo.PenalizacionPorHora = vehiculoDto.PenalizacionPorHora;
            vehiculo.Placa = vehiculoDto.Placa;
            vehiculo.Color = vehiculoDto.Color;
            vehiculo.Asientos = vehiculoDto.Asientos;

            if (!string.IsNullOrEmpty(vehiculoDto.ImagenBase64))
            {
                vehiculo.Imagen = Convert.FromBase64String(vehiculoDto.ImagenBase64);
            }

            _context.Vehiculos.Update(vehiculo);
            _context.SaveChanges();

            return Ok(new { message = "Vehículo actualizado correctamente" });
        }


        [HttpDelete("{id}")]
        public IActionResult DeleteVehiculo(int id)
        {
            var vehiculo = _context.Vehiculos.Find(id);
            if (vehiculo == null) return NotFound("Vehículo no encontrado");

            _context.Vehiculos.Remove(vehiculo);
            _context.SaveChanges();

            return Ok(new { message = "Vehículo eliminado correctamente" });
        }






        public class VehiculoDto
        {
            public int Id { get; set; }
            public string Marca { get; set; }
            public string Modelo { get; set; }
            public int Year { get; set; }
            public string Estado { get; set; }
            public decimal TarifaPorHora { get; set; }
            public decimal PenalizacionPorHora { get; set; }
            public string Placa { get; set; }
            public string Color { get; set; }
            public int Asientos { get; set; }
            public string ImagenBase64 { get; set; } // Imagen codificada en base64
        }

    }

}
